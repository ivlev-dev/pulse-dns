//! Парсер master-файла: директивы, наследование, `$INCLUDE`, валидация зоны.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use pulse_dns::{Name, Rclass, Rdata, Record, Rtype, TTL_MAX, Ttl};

use crate::error::{ErrorKind, Location, ParseError, Warning, WarningKind};
use crate::lexer::{Lexer, Line};
use crate::limits::Limits;
use crate::name::parse_name;
use crate::rdata::{parse_rdata, parse_rtype};
use crate::ttl::{looks_like_ttl, parse_duration};

/// Настройки разбора.
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// Лимиты ресурсов.
    pub limits: Limits,
    /// Каталог, внутри которого разрешены `$INCLUDE`.
    ///
    /// `None` запрещает `$INCLUDE`: директива возвращает явную ошибку.
    /// Пути include-файлов канонизируются и обязаны находиться внутри этого
    /// каталога (защита от `../` и симлинков).
    pub include_root: Option<PathBuf>,
    /// Проверять инварианты зоны (SOA/NS в apex, CNAME/DNAME).
    ///
    /// Для разбора фрагментов (без SOA) установите `false` или используйте
    /// [`parse_zone_fragment`].
    pub validate: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            include_root: None,
            validate: true,
        }
    }
}

/// Результат разбора master-файла.
#[derive(Debug, Clone)]
pub struct ParsedZone {
    /// Origin зоны (все владельцы — его поддомены, INV-7).
    pub origin: Name,
    /// TTL из `$TTL`, если директива присутствовала.
    ///
    /// TTL записей, у которых TTL не указан, разрешается по цепочке:
    /// `$TTL` → последний явный TTL → `SOA.minimum`.
    pub default_ttl: Option<Ttl>,
    /// Записи в порядке появления в файле.
    pub records: Vec<Record>,
    /// Некритичные замечания импорта (например, clamp TTL).
    pub warnings: Vec<Warning>,
}

impl ParsedZone {
    /// Первая SOA-запись зоны.
    #[must_use]
    pub fn soa(&self) -> Option<&Record> {
        self.records
            .iter()
            .find(|record| record.rr_type() == Rtype::SOA)
    }
}

/// Разбирает полный master-файл зоны со строгой валидацией.
///
/// # Errors
///
/// [`ParseError`] с файлом/строкой/колонкой при любой синтаксической или
/// семантической ошибке.
pub fn parse_zone(origin: Name, text: &str) -> Result<ParsedZone, ParseError> {
    parse_zone_with_options(origin, text, &ParseOptions::default())
}

/// Разбирает master-файл с настройками.
///
/// # Errors
///
/// [`ParseError`] при нарушении синтаксиса, лимитов или инвариантов зоны
/// (если [`ParseOptions::validate`] включена).
pub fn parse_zone_with_options(
    origin: Name,
    text: &str,
    options: &ParseOptions,
) -> Result<ParsedZone, ParseError> {
    if text.len() > options.limits.max_file_bytes {
        return Err(ParseError::new(
            Location::new("<input>", 1, 1),
            ErrorKind::Limit {
                what: "file size",
                value: text.len(),
                max: options.limits.max_file_bytes,
            },
        ));
    }
    let mut state = State {
        zone_origin: origin.clone(),
        records: Vec::new(),
        locations: Vec::new(),
        warnings: Vec::new(),
        soa_minimum: None,
        include_files: 0,
        default_ttl: None,
        include_root: canonical_include_root(options.include_root.as_deref()),
    };
    let base_dir = state
        .include_root
        .clone()
        .or_else(|| options.include_root.clone());
    let context = SourceContext {
        name: "<input>".to_owned(),
        base_dir,
    };
    let mut stack = Vec::new();
    parse_source(&mut state, text, origin, &context, options, 0, &mut stack)?;
    if options.validate {
        validate_zone(&state)?;
    }
    Ok(ParsedZone {
        origin: state.zone_origin,
        default_ttl: state.default_ttl,
        records: state.records,
        warnings: state.warnings,
    })
}

/// Разбирает фрагмент зоны без проверки SOA/NS в apex.
///
/// Синтаксис, лимиты, класс, TTL и принадлежность origin проверяются.
///
/// # Errors
///
/// [`ParseError`] при синтаксической или семантической ошибке записи.
pub fn parse_zone_fragment(origin: Name, text: &str) -> Result<ParsedZone, ParseError> {
    let options = ParseOptions {
        validate: false,
        ..ParseOptions::default()
    };
    parse_zone_with_options(origin, text, &options)
}

/// Разбирает фрагмент зоны с настройками.
///
/// # Errors
///
/// [`ParseError`] при нарушении синтаксиса или лимитов.
pub fn parse_zone_fragment_with_options(
    origin: Name,
    text: &str,
    options: &ParseOptions,
) -> Result<ParsedZone, ParseError> {
    let mut options = options.clone();
    options.validate = false;
    parse_zone_with_options(origin, text, &options)
}

struct State {
    zone_origin: Name,
    records: Vec<Record>,
    locations: Vec<Location>,
    warnings: Vec<Warning>,
    soa_minimum: Option<u32>,
    include_files: usize,
    default_ttl: Option<Ttl>,
    include_root: Option<PathBuf>,
}

struct SourceContext {
    name: String,
    base_dir: Option<PathBuf>,
}

#[allow(clippy::too_many_lines)]
fn parse_source(
    state: &mut State,
    text: &str,
    initial_origin: Name,
    context: &SourceContext,
    options: &ParseOptions,
    depth: usize,
    stack: &mut Vec<PathBuf>,
) -> Result<(), ParseError> {
    let mut lexer = Lexer::new(text, &context.name, options.limits);
    let mut origin = initial_origin;
    let mut previous_owner: Option<Name> = None;
    let mut last_ttl: Option<Ttl> = None;
    let mut last_class: Option<Rclass> = None;

    while let Some(line) = lexer.next_line()? {
        let Some(first) = line.tokens.first() else {
            continue;
        };
        if first.text.starts_with('$') {
            parse_directive(
                state,
                &line,
                &context.name,
                &mut origin,
                options,
                depth,
                stack,
                context,
            )?;
            continue;
        }

        let line_location = Location::new(&context.name, line.number, 1);
        let mut index = 0_usize;
        if line.indented {
            if previous_owner.is_none() {
                return Err(ParseError::new(line_location, ErrorKind::MissingOwner));
            }
        } else {
            let owner_token = first;
            let owner = parse_name(
                &owner_token.text,
                &origin,
                &owner_token.location(&context.name),
            )?;
            previous_owner = Some(owner);
            index = 1;
        }
        let Some(owner) = previous_owner.clone() else {
            return Err(ParseError::new(line_location, ErrorKind::MissingOwner));
        };

        let mut explicit_ttl: Option<Ttl> = None;
        let mut explicit_class: Option<Rclass> = None;
        for _ in 0..2 {
            let Some(token) = line.tokens.get(index) else {
                break;
            };
            if explicit_ttl.is_none() && looks_like_ttl(&token.text) {
                let location = token.location(&context.name);
                let value = parse_duration(&token.text).map_err(|message| {
                    ParseError::new(
                        location.clone(),
                        ErrorKind::Ttl {
                            input: token.text.clone(),
                            message,
                        },
                    )
                })?;
                explicit_ttl = Some(clamp_ttl(value, &location, state));
                index = index.saturating_add(1);
                continue;
            }
            if explicit_class.is_none() && looks_like_class(&token.text) {
                explicit_class = Some(parse_class(&token.text, &token.location(&context.name))?);
                index = index.saturating_add(1);
                continue;
            }
            break;
        }

        let Some(type_token) = line.tokens.get(index) else {
            return Err(ParseError::new(
                line_location,
                ErrorKind::MissingType {
                    owner: owner.to_string(),
                },
            ));
        };
        let rr_type = parse_rtype(&type_token.text, &type_token.location(&context.name))?;

        let rdata_tokens = line
            .tokens
            .get(index.saturating_add(1)..)
            .unwrap_or_default();
        if rdata_tokens.is_empty() {
            return Err(ParseError::new(
                type_token.location(&context.name),
                ErrorKind::Rdata {
                    rr_type,
                    message: "missing RDATA".to_owned(),
                },
            ));
        }
        let rdata = parse_rdata(rr_type, rdata_tokens, &context.name, &origin)?;

        let class = if let Some(class) = explicit_class {
            last_class = Some(class);
            class
        } else {
            last_class.unwrap_or(Rclass::IN)
        };

        let ttl = if let Some(ttl) = explicit_ttl {
            last_ttl = Some(ttl);
            ttl
        } else if let Some(ttl) = state.default_ttl {
            ttl
        } else if let Some(ttl) = last_ttl {
            ttl
        } else if let Some(minimum) = state.soa_minimum {
            Ttl::from_wire(minimum)
        } else if let Rdata::Soa(soa) = &rdata {
            clamp_ttl(soa.minimum, &line_location, state)
        } else {
            return Err(ParseError::new(line_location, ErrorKind::MissingTtl));
        };

        if !owner.is_subdomain_of(&state.zone_origin) {
            return Err(ParseError::new(
                line_location,
                ErrorKind::OutOfZone {
                    name: owner.to_string(),
                    origin: state.zone_origin.to_string(),
                },
            ));
        }
        owner.validate_zone_owner().map_err(|source| {
            ParseError::new(
                line_location.clone(),
                ErrorKind::Name {
                    input: owner.to_string(),
                    source,
                },
            )
        })?;

        let record = Record::new(owner, rr_type, class, ttl, rdata)
            .map_err(|source| ParseError::new(line_location.clone(), ErrorKind::Record(source)))?;
        if let Rdata::Soa(soa) = record.rdata() {
            state.soa_minimum = Some(soa.minimum);
        }
        if state.records.len() >= options.limits.max_records {
            return Err(ParseError::new(
                line_location,
                ErrorKind::Limit {
                    what: "records",
                    value: state.records.len().saturating_add(1),
                    max: options.limits.max_records,
                },
            ));
        }
        state.records.push(record);
        state.locations.push(line_location);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_directive(
    state: &mut State,
    line: &Line,
    source: &str,
    origin: &mut Name,
    options: &ParseOptions,
    depth: usize,
    stack: &mut Vec<PathBuf>,
    context: &SourceContext,
) -> Result<(), ParseError> {
    let Some(first) = line.tokens.first() else {
        return Ok(());
    };
    let location = first.location(source);
    let name = first.text.to_ascii_uppercase();
    match name.as_str() {
        "$ORIGIN" => {
            let Some(token) = line.tokens.get(1) else {
                return Err(directive_error(
                    "$ORIGIN",
                    "expected a domain name",
                    &location,
                ));
            };
            if line.tokens.len() != 2 {
                return Err(directive_error(
                    "$ORIGIN",
                    "expected exactly one domain name",
                    &location,
                ));
            }
            *origin = parse_name(&token.text, origin, &token.location(source))?;
        }
        "$TTL" => {
            let Some(token) = line.tokens.get(1) else {
                return Err(directive_error("$TTL", "expected a TTL value", &location));
            };
            if line.tokens.len() != 2 {
                return Err(directive_error(
                    "$TTL",
                    "expected exactly one TTL value",
                    &location,
                ));
            }
            let value = parse_duration(&token.text).map_err(|message| {
                ParseError::new(
                    token.location(source),
                    ErrorKind::Ttl {
                        input: token.text.clone(),
                        message,
                    },
                )
            })?;
            state.default_ttl = Some(clamp_ttl(value, &token.location(source), state));
        }
        "$INCLUDE" => {
            let Some(path_token) = line.tokens.get(1) else {
                return Err(directive_error(
                    "$INCLUDE",
                    "expected a file path",
                    &location,
                ));
            };
            if line.tokens.len() > 3 {
                return Err(directive_error(
                    "$INCLUDE",
                    "expected path and optional origin",
                    &location,
                ));
            }
            let include_origin = match line.tokens.get(2) {
                Some(token) => parse_name(&token.text, origin, &token.location(source))?,
                None => origin.clone(),
            };
            include(
                state,
                path_token,
                source,
                include_origin,
                options,
                depth,
                stack,
                context,
            )?;
        }
        "$GENERATE" => {
            return Err(ParseError::new(
                location,
                ErrorKind::UnsupportedDirective("$GENERATE".to_owned()),
            ));
        }
        _ => {
            return Err(ParseError::new(
                location,
                ErrorKind::UnknownDirective(first.text.clone()),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn include(
    state: &mut State,
    path_token: &crate::lexer::Token,
    source: &str,
    include_origin: Name,
    options: &ParseOptions,
    depth: usize,
    stack: &mut Vec<PathBuf>,
    context: &SourceContext,
) -> Result<(), ParseError> {
    let location = path_token.location(source);
    let Some(root) = state.include_root.clone() else {
        return Err(ParseError::new(
            location,
            ErrorKind::Include(
                "is disabled: set ParseOptions::include_root to a directory".to_owned(),
            ),
        ));
    };
    if depth >= options.limits.max_include_depth {
        return Err(ParseError::new(
            location,
            ErrorKind::Include(format!(
                "nesting depth {} exceeds limit {}",
                depth.saturating_add(1),
                options.limits.max_include_depth
            )),
        ));
    }
    if state.include_files >= options.limits.max_include_files {
        return Err(ParseError::new(
            location,
            ErrorKind::Limit {
                what: "include files",
                value: state.include_files.saturating_add(1),
                max: options.limits.max_include_files,
            },
        ));
    }
    let raw_path = crate::name::decode_string_raw(&path_token.text).map_err(|message| {
        ParseError::new(
            location.clone(),
            ErrorKind::Include(format!("invalid path escape: {message}")),
        )
    })?;
    let text_path = String::from_utf8(raw_path).map_err(|_| {
        ParseError::new(
            location.clone(),
            ErrorKind::Include("path is not valid UTF-8".to_owned()),
        )
    })?;
    let requested = Path::new(&text_path);
    let base_dir = context.base_dir.as_deref().unwrap_or(root.as_path());
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        base_dir.join(requested)
    };
    let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
        ParseError::new(
            location.clone(),
            ErrorKind::Io(format!("{}: {error}", candidate.display())),
        )
    })?;
    if !canonical.starts_with(&root) {
        return Err(ParseError::new(
            location,
            ErrorKind::Include(format!(
                "path {} escapes include root {}",
                canonical.display(),
                root.display()
            )),
        ));
    }
    if stack.iter().any(|path| path == &canonical) {
        return Err(ParseError::new(
            location,
            ErrorKind::Include(format!("include cycle at {}", canonical.display())),
        ));
    }
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        ParseError::new(
            location.clone(),
            ErrorKind::Io(format!("{}: {error}", canonical.display())),
        )
    })?;
    let Ok(length) = usize::try_from(metadata.len()) else {
        return Err(ParseError::new(
            location,
            ErrorKind::Limit {
                what: "file size",
                value: usize::MAX,
                max: options.limits.max_file_bytes,
            },
        ));
    };
    if length > options.limits.max_file_bytes {
        return Err(ParseError::new(
            location,
            ErrorKind::Limit {
                what: "file size",
                value: length,
                max: options.limits.max_file_bytes,
            },
        ));
    }
    let included = std::fs::read_to_string(&canonical).map_err(|error| {
        ParseError::new(
            location.clone(),
            ErrorKind::Io(format!("{}: {error}", canonical.display())),
        )
    })?;
    state.include_files = state.include_files.saturating_add(1);
    let nested = SourceContext {
        name: canonical.display().to_string(),
        base_dir: canonical.parent().map(Path::to_path_buf),
    };
    stack.push(canonical);
    let result = parse_source(
        state,
        &included,
        include_origin,
        &nested,
        options,
        depth.saturating_add(1),
        stack,
    );
    stack.pop();
    result
}

fn clamp_ttl(value: u32, location: &Location, state: &mut State) -> Ttl {
    if value > TTL_MAX {
        state.warnings.push(Warning {
            location: location.clone(),
            kind: WarningKind::TtlClamped { value },
        });
    }
    Ttl::from_wire(value)
}

fn looks_like_class(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    matches!(upper.as_str(), "IN" | "CH" | "HS")
        || upper
            .strip_prefix("CLASS")
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_class(text: &str, location: &Location) -> Result<Rclass, ParseError> {
    let upper = text.to_ascii_uppercase();
    let class = match upper.as_str() {
        "IN" => Rclass::IN,
        "CH" => Rclass::CH,
        "HS" => Rclass::HS,
        other => {
            let digits = other
                .strip_prefix("CLASS")
                .and_then(|digits| digits.parse::<u16>().ok())
                .ok_or_else(|| {
                    ParseError::new(
                        location.clone(),
                        ErrorKind::UnsupportedClass(text.to_owned()),
                    )
                })?;
            Rclass::from_u16(digits)
        }
    };
    if class != Rclass::IN {
        return Err(ParseError::new(
            location.clone(),
            ErrorKind::UnsupportedClass(text.to_owned()),
        ));
    }
    Ok(class)
}

fn directive_error(directive: &'static str, message: &str, location: &Location) -> ParseError {
    ParseError::new(
        location.clone(),
        ErrorKind::Directive {
            directive,
            message: message.to_owned(),
        },
    )
}

fn canonical_include_root(root: Option<&Path>) -> Option<PathBuf> {
    root.and_then(|path| std::fs::canonicalize(path).ok())
}

fn validate_zone(state: &State) -> Result<(), ParseError> {
    let mut soa_indices = Vec::new();
    let mut apex_ns = 0_usize;
    let mut owners: HashMap<Name, (bool, bool, HashSet<Rtype>)> = HashMap::new();

    for (index, record) in state.records.iter().enumerate() {
        let is_apex = record.owner() == &state.zone_origin;
        match record.rr_type() {
            Rtype::SOA => soa_indices.push(index),
            Rtype::NS if is_apex => apex_ns = apex_ns.saturating_add(1),
            _ => {}
        }
        let entry = owners
            .entry(record.owner().clone())
            .or_insert_with(|| (false, false, HashSet::new()));
        entry.2.insert(record.rr_type());
        if record.rr_type() == Rtype::CNAME {
            entry.0 = true;
        }
        if record.rr_type() == Rtype::DNAME {
            entry.1 = true;
        }
    }

    match soa_indices.as_slice() {
        [] => {
            return Err(ParseError::new(
                Location::unknown("<zone>"),
                ErrorKind::Validation(format!(
                    "zone {} has no SOA record at apex",
                    state.zone_origin
                )),
            ));
        }
        [index] => {
            let record = state.records.get(*index);
            if record.is_some_and(|record| record.owner() != &state.zone_origin) {
                return Err(ParseError::new(
                    location_at(state, *index),
                    ErrorKind::Validation(format!("SOA must be at apex {}", state.zone_origin)),
                ));
            }
        }
        _ => {
            return Err(ParseError::new(
                location_at(state, *soa_indices.get(1).unwrap_or(&0)),
                ErrorKind::Validation("zone has more than one SOA record".to_owned()),
            ));
        }
    }

    if apex_ns == 0 {
        return Err(ParseError::new(
            Location::unknown("<zone>"),
            ErrorKind::Validation(format!(
                "zone {} has no NS record at apex",
                state.zone_origin
            )),
        ));
    }

    for (index, record) in state.records.iter().enumerate() {
        let Some((has_cname, has_dname, types)) = owners.get(record.owner()) else {
            continue;
        };
        if *has_cname && record.owner() == &state.zone_origin {
            return Err(ParseError::new(
                location_at(state, index),
                ErrorKind::Validation("CNAME is not allowed at zone apex".to_owned()),
            ));
        }
        if *has_cname && *has_dname {
            return Err(ParseError::new(
                location_at(state, index),
                ErrorKind::Validation(
                    "DNAME and CNAME cannot coexist at the same owner".to_owned(),
                ),
            ));
        }
        if *has_dname && record.owner() == &state.zone_origin {
            return Err(ParseError::new(
                location_at(state, index),
                ErrorKind::Validation("DNAME is not allowed at zone apex".to_owned()),
            ));
        }
        if *has_cname {
            let allowed = [Rtype::CNAME, Rtype::RRSIG, Rtype::NSEC, Rtype::NSEC3];
            if types.iter().any(|rr_type| !allowed.contains(rr_type)) {
                return Err(ParseError::new(
                    location_at(state, index),
                    ErrorKind::Validation(format!(
                        "CNAME owner {} has other data than CNAME/RRSIG/NSEC/NSEC3",
                        record.owner()
                    )),
                ));
            }
        }
    }
    Ok(())
}

fn location_at(state: &State, index: usize) -> Location {
    state
        .locations
        .get(index)
        .cloned()
        .unwrap_or_else(|| Location::unknown("<zone>"))
}
