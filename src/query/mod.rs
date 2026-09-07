//! Query DSL — hand-written tokenizer + recursive-descent parser (no nom).
//!
//! Grammar: `call := IDENT '(' args ')'`; `args := (STRING|call) (',' (STRING|call))*`

use crate::core::hlc::Hlc;
use crate::core::ident::PublicKey;
use crate::storage::{ConflictPolicy, Entry, StorageError, Store, Version};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    List(Vec<Value>),
}

impl Value {
    /// JSON representation: `null`/`true`/`N`/`"s"`/`[...]`.
    pub fn json(&self) -> String {
        match self {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Num(n) => n.to_string(),
            Value::Str(s) => format!("{:?}", s),
            Value::List(xs) => format!(
                "[{}]",
                xs.iter().map(|v| v.json()).collect::<Vec<_>>().join(",")
            ),
        }
    }
}

#[derive(Debug)]
pub enum QueryError {
    Parse { line: usize, col: usize, msg: String },
    UnknownFn(String),
    Type(String),
    Eval(StorageError),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::Parse { line, col, msg } => write!(f, "parse error at {line}:{col}: {msg}"),
            QueryError::UnknownFn(n) => write!(f, "unknown function: {n}"),
            QueryError::Type(m) => write!(f, "type error: {m}"),
            QueryError::Eval(e) => write!(f, "eval error: {e}"),
        }
    }
}

impl From<StorageError> for QueryError {
    fn from(e: StorageError) -> QueryError {
        QueryError::Eval(e)
    }
}

/// The store handle a query context runs against. `Write` for statements
/// that mutate (needs the daemon's store write lock), `Read` for pure reads
/// (read lock only). Splitting at the context level is what lets an
/// authenticated `/ql` read query run without stalling every other request
/// on the node's single write lock (LOCK-ACROSS-BATCH-007).
pub enum StoreRef<'a> {
    Read(&'a Store),
    Write(&'a mut Store),
}

/// Statement kind, computed by [`classify`] before a lock is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StmtKind {
    ReadOnly,
    Mutating,
}

pub struct QueryCtx<'a> {
    pub store: StoreRef<'a>,
    pub scope: Option<String>,
    pub host_id: PublicKey,
    /// Set for the HTTP `/ql` path (cap-authenticated). When true, the
    /// admin-privileged `use`/`create_ns` functions are refused: a remote
    /// caller must not be able to move the DSL scope outside the namespace
    /// its capability authorizes, nor create namespaces (an L1/admin op).
    /// The REPL drives the store locally and keeps them.
    pub remote: bool,
}

impl<'a> QueryCtx<'a> {
    /// Read view of the store — valid for either arm.
    pub fn store_ref(&self) -> &Store {
        match &self.store {
            StoreRef::Read(store) => *store,
            StoreRef::Write(store) => *store,
        }
    }

    /// Mutable view of the store. Only valid for a [`StoreRef::Write`]
    /// context; reaching this on a read context is a bug (classify()
    /// guarantees a mutable statement gets a write context). It surfaces as
    /// a query error rather than a panic, so a mis-classification can never
    /// corrupt anything — it fails closed.
    pub fn store_mut(&mut self) -> Result<&mut Store, QueryError> {
        match &mut self.store {
            StoreRef::Write(store) => Ok(store),
            StoreRef::Read(_) => Err(QueryError::Type(
                "store is read-only in this context, but the statement mutates".to_string()
            )),
        }
    }
}

/// Evaluate a single expression.
pub fn eval(ctx: &mut QueryCtx, src: &str) -> Result<Value, QueryError> {
    let mut toks = Tokenizer::new(src);
    let call = toks
        .parse_call()?
        .ok_or_else(|| QueryError::Parse { line: toks.line, col: toks.col, msg: "empty expression".into() })?;
    toks.expect_end()?;
    exec(ctx, &call)
}

/// Mutating function names (the remote `/ql` reachable ones — `use` and
/// `create_ns` are already refused for remote callers before they can
/// mutate). Used by [`classify`] to pick the store lock.
fn is_mutator(name: &str) -> bool {
    name == "put" || name == "del" || name == "index_create" || name == "index_drop"
}

fn contains_mutator(call: &Call) -> bool {
    if is_mutator(call.name.as_str()) {
        return true;
    }
    // Args may be nested calls (`get(put("k","v"))`); walk the whole tree so
    // a mutator buried in an argument still classifies as Mutating.
    for arg in &call.args {
        match arg {
            Arg::Call(c) => {
                if contains_mutator(&c) {
                    return true;
                }
            }
            Arg::Str(_) => {}
        }
    }
    false
}

/// Parse `src` (same grammar as [`eval`]) and report whether the statement
/// mutates. Called by the `/ql` handler BEFORE acquiring a store lock: a
/// ReadOnly verdict guarantees `eval` can never mutate, so it may run under
/// a read lock; anything else takes the write lock. Fail-closed on parse
/// errors.
pub fn classify(src: &str) -> Result<StmtKind, QueryError> {
    let mut toks = Tokenizer::new(src);
    let call = toks
        .parse_call()?
        .ok_or_else(|| QueryError::Parse { line: toks.line, col: toks.col, msg: "empty expression".into() })?;
    toks.expect_end()?;
    Ok(if contains_mutator(&call) { StmtKind::Mutating } else { StmtKind::ReadOnly })
}

// ---------- execution ----------

fn exec(ctx: &mut QueryCtx, call: &Call) -> Result<Value, QueryError> {
    match call.name.as_str() {
        "now" => {
            argc(call, 0)?;
            Ok(Value::Num(Hlc::now().ms()))
        }
        "hlc" => {
            argc(call, 0)?;
            Ok(Value::Num(Hlc::now().to_u64()))
        }
        "before" => {
            argc(call, 2)?;
            let a = num_arg(ctx, &call.args[0])?;
            let b = num_arg(ctx, &call.args[1])?;
            Ok(Value::Bool(a < b))
        }
        "clock_skew" => {
            argc(call, 1)?;
            let host = str_arg(ctx, &call.args[0])?;
            // M3: peer-clock estimate from sync; Null before any Hello sample.
            match ctx.store_ref().peer_clock(&host) {
                // Estimate = how far ahead the peer's clock is; clamp
                // negatives to 0 (peer behind ⇒ no meaningful positive skew).
                Some(diff) => Ok(Value::Num(diff.max(0) as u64)),
                None => Ok(Value::Null),
            }
        }
        "use" => {
            argc(call, 1)?;
            if ctx.remote {
                // Cap-authenticated /ql: the caller was authorized for the
                // request's namespace; changing scope would escape it.
                return Err(QueryError::Type("use() is not available over the HTTP ql API".to_string()));
            }
            let ns = str_arg(ctx, &call.args[0])?;
            if ctx.store_ref().policy(&ns).is_none() {
                return Err(QueryError::Eval(StorageError::NotFound(ns)));
            }
            ctx.scope = Some(ns);
            Ok(Value::Bool(true))
        }
        "create_ns" => {
            argc(call, 1)?;
            if ctx.remote {
                // Creating a namespace is an L1/admin operation; a remote
                // caller must use the admin route, not the data ql API.
                return Err(QueryError::Type("create_ns() is not available over the HTTP ql API".to_string()));
            }
            let ns = str_arg(ctx, &call.args[0])?;
            ctx.store_mut()?
                .create_namespace(&ns, ConflictPolicy::Lww)
                .map_err(QueryError::Eval)?;
            Ok(Value::Bool(true))
        }
        "get" => {
            argc(call, 1)?;
            let ns = scope(ctx)?;
            let key = str_arg(ctx, &call.args[0])?.into_bytes();
            match ctx.store_ref().get(&ns, &key) {
                None => Ok(Value::Null),
                Some(e) => Ok(Value::Str(
                    latest_version(e)
                        .map(|v| String::from_utf8_lossy(&v.value).into_owned())
                        .unwrap_or_default(),
                )),
            }
        }
        "put" => {
            argc(call, 2)?;
            let ns = scope(ctx)?;
            let key = str_arg(ctx, &call.args[0])?.into_bytes();
            let val = str_arg(ctx, &call.args[1])?.into_bytes();
            let hlc = Hlc::now().to_u64();
            let rid = ctx.host_id.to_bytes();
            ctx.store_mut()?.put(&ns, &key, &val, hlc, rid, rid, 0)?;
            Ok(Value::Bool(true))
        }
        "del" => {
            argc(call, 1)?;
            let ns = scope(ctx)?;
            let key = str_arg(ctx, &call.args[0])?.into_bytes();
            let hlc = Hlc::now().to_u64();
            let rid = ctx.host_id.to_bytes();
            ctx.store_mut()?.delete(&ns, &key, hlc, rid, rid)?;
            Ok(Value::Bool(true))
        }
        "scan" => {
            argc(call, 1)?;
            let ns = scope(ctx)?;
            let prefix = str_arg(ctx, &call.args[0])?.into_bytes();
            let rows = ctx.store_ref().scan(&ns, &prefix);
            let mut out = Vec::with_capacity(rows.len() * 2);
            for (k, e) in rows {
                out.push(Value::Str(String::from_utf8_lossy(&k).into_owned()));
                out.push(Value::Str(
                    latest_version(&e)
                        .map(|v| String::from_utf8_lossy(&v.value).into_owned())
                        .unwrap_or_default(),
                ));
            }
            Ok(Value::List(out))
        }
        "get_all" => {
            argc(call, 1)?;
            let ns = scope(ctx)?;
            let key = str_arg(ctx, &call.args[0])?.into_bytes();
            match ctx.store_ref().get(&ns, &key) {
                Some(Entry::Lww(v)) => Ok(Value::List(vec![
                    Value::Str(hex::encode(v.replica)),
                    Value::Num(v.hlc),
                    Value::Str(String::from_utf8_lossy(&v.value).into_owned()),
                ])),
                Some(Entry::Register(vs)) => {
                    let mut out = Vec::with_capacity(vs.len() * 3);
                    for v in vs {
                        out.push(Value::Str(hex::encode(v.replica)));
                        out.push(Value::Num(v.hlc));
                        out.push(Value::Str(String::from_utf8_lossy(&v.value).into_owned()));
                    }
                    Ok(Value::List(out))
                }
                None => Ok(Value::Null),
            }
        }
        "index_create" => {
            // index_create(field[, field...]) — define a primary secondary
            // index on scalar JSON fields of the current scope's namespace.
            // Requires a write-scope caller. The definition replicates; the
            // index itself is derived from values on every peer.
            if call.args.is_empty() {
                return Err(QueryError::Type("index_create(field[, field...])".to_string()));
            }
            let ns = scope(ctx)?;
            let mut fields: Vec<String> = Vec::with_capacity(call.args.len());
            for a in &call.args {
                fields.push(str_arg(ctx, a)?);
            }
            let hlc = Hlc::now().to_u64();
            let rid = ctx.host_id.to_bytes();
            let value = serde_json::to_vec(&fields).expect("index fields");
            ctx.store_mut()?.set_index(&ns, Some(&value), hlc, rid, rid)?;
            Ok(Value::Bool(true))
        }
        "index_fields" => {
            // index_fields(ns?) — list the namespace's indexed fields.
            let ns = scope(ctx)?;
            let fields = match ctx.store_ref().index_def(&ns) {
                Some(b) => {
                    let s = String::from_utf8_lossy(b).into_owned();
                    match serde_json::from_str::<Vec<String>>(&s) {
                        Ok(fs) => fs,
                        Err(_) => Vec::new(),
                    }
                }
                None => Vec::new(),
            };
            Ok(Value::List(fields.iter().map(|f| Value::Str(f.clone())).collect::<Vec<_>>()))
        }
        "index_drop" => {
            // index_drop(ns?) — clear the secondary index definition.
            let ns = scope(ctx)?;
            let hlc = Hlc::now().to_u64();
            let rid = ctx.host_id.to_bytes();
            ctx.store_mut()?.set_index(&ns, None, hlc, rid, rid)?;
            Ok(Value::Bool(true))
        }
        "by_index" => {
            // by_index(field, value, ns?) — rows where the indexed FIELD's
            // value equals VALUE, resolved via the secondary index. Field
            // values are scalar JSON extractions (string/number/bool) from
            // each stored value; a value with no such field simply isn't
            // indexed. Returns [key, ...] for matching sorted rows.
            if call.args.len() < 2 || call.args.len() > 3 {
                return Err(QueryError::Type("by_index(field, value[, ns])".to_string()));
            }
            let ns = scope(ctx)?;
            let field = str_arg(ctx, &call.args[0])?;
            let want = str_arg(ctx, &call.args[1])?.into_bytes();
            let rows = ctx.store_ref().index_lookup(&ns, &field, &want);
            // index_lookup returns (fieldvalue, key) >= want; keep exact runs.
            let mut out = Vec::with_capacity(rows.len());
            for (fv, k) in rows {
                if fv != want {
                    break; // sorted; once past the match, nothing more matches
                }
                out.push(Value::Str(String::from_utf8_lossy(&k).into_owned()));
            }
            Ok(Value::List(out))
        }
        other => Err(QueryError::UnknownFn(other.to_string())),
    }
}

/// Latest version of an entry by (hlc, replica) — converges across nodes.
fn latest_version(e: &Entry) -> Option<&Version> {
    match e {
        Entry::Lww(v) => Some(v),
        Entry::Register(vs) => vs.iter().max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica))),
    }
}

fn scope(ctx: &QueryCtx) -> Result<String, QueryError> {
    ctx.scope
        .clone()
        .ok_or(QueryError::Eval(StorageError::NoScope))
}

fn argc(call: &Call, n: usize) -> Result<(), QueryError> {
    if call.args.len() != n {
        return Err(QueryError::Type(format!(
            "{}() takes {n} argument(s), got {}",
            call.name,
            call.args.len()
        )));
    }
    Ok(())
}

fn str_arg(ctx: &mut QueryCtx, arg: &Arg) -> Result<String, QueryError> {
    match arg {
        Arg::Str(s) => Ok(s.clone()),
        Arg::Call(c) => match exec(ctx, c)? {
            Value::Str(s) => Ok(s),
            other => Err(QueryError::Type(format!(
                "expected string from {}, got {other:?}",
                c.name
            ))),
        },
    }
}

fn num_arg(ctx: &mut QueryCtx, arg: &Arg) -> Result<u64, QueryError> {
    match arg {
        Arg::Str(s) => s
            .parse::<u64>()
            .map_err(|_| QueryError::Type(format!("expected number, got string {s:?}"))),
        Arg::Call(c) => match exec(ctx, c)? {
            Value::Num(n) => Ok(n),
            other => Err(QueryError::Type(format!("expected Num from {}, got {other:?}", c.name))),
        },
    }
}

// ---------- tokenizer + parser ----------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Comma,
}

#[derive(Debug, Clone, PartialEq)]
enum Arg {
    Str(String),
    Call(Call),
}

#[derive(Debug, Clone, PartialEq)]
struct Call {
    name: String,
    args: Vec<Arg>,
}

struct Tokenizer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Tokenizer<'a> {
    fn new(src: &'a str) -> Tokenizer<'a> {
        Tokenizer { src: src.as_bytes(), pos: 0, line: 1, col: 1 }
    }

    fn err(&self, msg: impl Into<String>) -> QueryError {
        QueryError::Parse { line: self.line, col: self.col, msg: msg.into() }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        if c == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn token(&mut self) -> Result<Option<Tok>, QueryError> {
        self.skip_ws();
        match self.peek() {
            None => Ok(None),
            Some(b'(') => {
                self.bump();
                Ok(Some(Tok::LParen))
            }
            Some(b')') => {
                self.bump();
                Ok(Some(Tok::RParen))
            }
            Some(b',') => {
                self.bump();
                Ok(Some(Tok::Comma))
            }
            Some(b'"') => {
                self.bump();
                let mut s = Vec::new();
                loop {
                    match self.bump() {
                        None => return Err(self.err("unterminated string")),
                        Some(b'"') => break,
                        Some(b'\\') => match self.bump() {
                            Some(b'"') => s.push(b'"'),
                            Some(b'\\') => s.push(b'\\'),
                            Some(b'n') => s.push(b'\n'),
                            Some(b't') => s.push(b'\t'),
                            Some(c) => {
                                return Err(self.err(format!("invalid escape \\{}", c as char)))
                            }
                            None => return Err(self.err("unterminated string")),
                        },
                        Some(c) => s.push(c),
                    }
                }
                Ok(Some(Tok::Str(String::from_utf8_lossy(&s).into_owned())))
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let mut name = Vec::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == b'_' {
                        name.push(c);
                        self.bump();
                    } else {
                        break;
                    }
                }
                Ok(Some(Tok::Ident(String::from_utf8_lossy(&name).into_owned())))
            }
            Some(c) => Err(self.err(format!("unexpected character {:?}", c as char))),
        }
    }

    /// Parse one top-level call, leaving trailing tokens for `expect_end`.
    fn parse_call(&mut self) -> Result<Option<Call>, QueryError> {
        self.skip_ws();
        if self.peek().is_none() {
            return Ok(None);
        }
        Ok(Some(self.parse_call_inner()?))
    }

    fn parse_call_inner(&mut self) -> Result<Call, QueryError> {
        let name = match self.token()? {
            Some(Tok::Ident(n)) => n,
            Some(other) => return Err(self.err(format!("expected function name, got {other:?}"))),
            None => return Err(self.err("empty expression")),
        };
        self.parse_named_call(name)
    }

    /// Parse `( args )` for a call whose name was already consumed.
    fn parse_named_call(&mut self, name: String) -> Result<Call, QueryError> {
        match self.token()? {
            Some(Tok::LParen) => {}
            other => return Err(self.err(format!("expected '(' after {name}, got {other:?}"))),
        }
        let mut args: Vec<Arg> = Vec::new();
        loop {
            match self.token()? {
                None => return Err(self.err("unterminated call: missing ')'")),
                Some(Tok::RParen) => break,
                Some(Tok::Comma) => {
                    if args.is_empty() {
                        return Err(self.err("unexpected ','"));
                    }
                    // next iteration parses the next argument
                }
                Some(Tok::Str(s)) => args.push(Arg::Str(s)),
                Some(Tok::Ident(n)) => args.push(Arg::Call(self.parse_named_call(n)?)),
                Some(Tok::LParen) => return Err(self.err("expected argument, got '('")),
            }
        }
        Ok(Call { name, args })
    }

    fn expect_end(&mut self) -> Result<(), QueryError> {
        self.skip_ws();
        if self.peek().is_some() {
            return Err(self.err("trailing tokens after expression"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bmd-query-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn ctx<'a>(store: &'a mut Store) -> QueryCtx<'a> {
        let host = PublicKey::from_bytes([9u8; 32]);
        QueryCtx { store: StoreRef::Write(store), scope: None, host_id: host, remote: false }
    }

    #[test]
    fn classify_detects_mutators_including_nested() {
        assert_eq!(classify("get(\"k\")").unwrap(), StmtKind::ReadOnly);
        assert_eq!(classify("by_index(\"f\", \"v\")").unwrap(), StmtKind::ReadOnly);
        assert_eq!(classify("put(\"k\", \"v\")").unwrap(), StmtKind::Mutating);
        assert_eq!(classify("del(\"k\")").unwrap(), StmtKind::Mutating);
        assert_eq!(classify("index_create(\"f\")").unwrap(), StmtKind::Mutating);
        assert_eq!(classify("index_drop()").unwrap(), StmtKind::Mutating);
        // A mutator buried in a nested argument still classifies Mutating —
        // this is the soundness property that lets run_ql trust a ReadOnly
        // verdict to run under a read lock.
        assert_eq!(classify("get(put(\"k\", \"v\"))").unwrap(), StmtKind::Mutating);
        // Read-only functions with nested call args stay ReadOnly (note: bare
        // numeric literals are not a valid arg — strings and calls only).
        assert_eq!(classify("before(get(\"a\"), get(\"b\"))").unwrap(), StmtKind::ReadOnly);
        assert!(classify("nope(").is_err());
    }

    #[test]
    fn readonly_ctx_serves_reads_and_fails_closed_on_mutation() {
        let dir = tmpdir("roctx");
        let mut s = Store::open(&dir).unwrap();
        let host = PublicKey::from_bytes([9u8; 32]);
        s.create_namespace("photos", ConflictPolicy::Lww).unwrap();
        // Seed via a write ctx.
        let mut wc = ctx(&mut s);
        assert_eq!(eval(&mut wc, "use(\"photos\")").map(|v| v.json()).unwrap(), "true");
        assert_eq!(eval(&mut wc, "put(\"1\",\"hello\")").map(|v| v.json()).unwrap(), "true");

        // A read-only context is enough for reads...
        let mut scope_rc = QueryCtx {
            store: StoreRef::Read(&s),
            scope: Some("photos".to_string()),
            host_id: host,
            remote: true,
        };
        assert_eq!(eval(&mut scope_rc, "get(\"1\")").map(|v| v.json()).unwrap(), "\"hello\"");
        // ...and a mutator under a Read context fails closed (defensive;
        // run_ql's classify guarantees this never happens for real).
        assert!(eval(&mut scope_rc, "put(\"2\",\"x\")").is_err());
    }

    #[test]
    fn every_function() {
        let dir = tmpdir("fns");
        let mut s = Store::open(&dir).unwrap();
        let host = PublicKey::from_bytes([9u8; 32]);
        let mut c = QueryCtx { store: StoreRef::Write(&mut s), scope: None, host_id: host, remote: false };
        let r = |c: &mut QueryCtx, src: &str| eval(c, src).map(|v| v.json());
        assert_eq!(r(&mut c, "create_ns(\"photos\")").unwrap(), "true");
        assert_eq!(r(&mut c, "use(\"photos\")").unwrap(), "true");
        assert_eq!(r(&mut c, "put(\"1\",\"hello\")").unwrap(), "true");
        assert_eq!(r(&mut c, "get(\"1\")").unwrap(), "\"hello\"");
        assert_eq!(r(&mut c, "scan(\"\")").unwrap(), "[\"1\",\"hello\"]");
        assert_eq!(r(&mut c, "del(\"1\")").unwrap(), "true");
        assert_eq!(r(&mut c, "get(\"1\")").unwrap(), "null");
        assert_eq!(r(&mut c, "scan(\"\")").unwrap(), "[]");
        // now/hlc/before as numbers
        assert!(r(&mut c, "now()").unwrap().parse::<u64>().is_ok());
        assert!(r(&mut c, "hlc()").unwrap().parse::<u64>().is_ok());
        assert_eq!(r(&mut c, "before(now(), hlc())").unwrap(), "true");
        assert_eq!(r(&mut c, "before(hlc(), now())").unwrap(), "false");
        // clock_skew always Null in M1
        assert_eq!(r(&mut c, "clock_skew(\"node2\")").unwrap(), "null");
        // string escapes
        assert_eq!(r(&mut c, "put(\"q\",\"a\\\"b\")").unwrap(), "true");
        assert_eq!(r(&mut c, "get(\"q\")").unwrap(), "\"a\\\"b\"");
        // before with string-literal numbers (deterministic)
        assert_eq!(r(&mut c, "before(\"1\",\"2\")").unwrap(), "true");
        assert_eq!(r(&mut c, "before(\"2\",\"1\")").unwrap(), "false");
        // nested call as argument
        assert_eq!(r(&mut c, "before(\"1\", now())").unwrap(), "true");
    }

    #[test]
    fn parse_and_scope_errors() {
        let dir = tmpdir("errs");
        let mut s = Store::open(&dir).unwrap();
        // missing scope
        match eval(&mut ctx(&mut s), "get(\"a\")") {
            Err(QueryError::Eval(StorageError::NoScope)) => {}
            other => panic!("expected NoScope, got {other:?}"),
        }
        // unknown fn
        match eval(&mut ctx(&mut s), "grant(\"x\")") {
            Err(QueryError::UnknownFn(n)) => assert_eq!(n, "grant"),
            other => panic!("expected UnknownFn, got {other:?}"),
        }
        // unterminated string → Parse
        match eval(&mut ctx(&mut s), "put(\"abc") {
            Err(QueryError::Parse { msg, .. }) => assert!(msg.contains("unterminated"), "{msg}"),
            other => panic!("expected Parse, got {other:?}"),
        }
        // unbalanced paren
        match eval(&mut ctx(&mut s), "now(") {
            Err(QueryError::Parse { .. }) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
        // trailing tokens
        match eval(&mut ctx(&mut s), "now() extra") {
            Err(QueryError::Parse { .. }) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
        // use() on missing ns
        match eval(&mut ctx(&mut s), "use(\"nope\")") {
            Err(QueryError::Eval(StorageError::NotFound(n))) => assert_eq!(n, "nope"),
            other => panic!("expected NotFound, got {other:?}"),
        }
        // wrong arity
        match eval(&mut ctx(&mut s), "now(\"x\")") {
            Err(QueryError::Type(_)) => {}
            other => panic!("expected Type, got {other:?}"),
        }
    }

    #[test]
    fn put_get_scan_persist_across_reopen() {
        let dir = tmpdir("persist");
        {
            let mut s = Store::open(&dir).unwrap();
            let mut c = ctx(&mut s);
            eval(&mut c, "create_ns(\"n\")").unwrap();
            eval(&mut c, "use(\"n\")").unwrap();
            eval(&mut c, "put(\"a\",\"1\")").unwrap();
            eval(&mut c, "put(\"b/c\",\"2\")").unwrap();
        }
        let mut s = Store::open(&dir).unwrap();
        let mut c = ctx(&mut s);
        eval(&mut c, "use(\"n\")").unwrap();
        assert_eq!(eval(&mut c, "get(\"a\")").unwrap().json(), "\"1\"");
        let rows = eval(&mut c, "scan(\"b\")").unwrap();
        assert_eq!(rows, Value::List(vec![Value::Str("b/c".into()), Value::Str("2".into())]));
    }

    #[test]
    fn secondary_index_derived_and_queried() {
        let dir = tmpdir("secidx");
        {
            let mut s = Store::open(&dir).unwrap();
            let mut c = ctx(&mut s);
            eval(&mut c, "create_ns(\"people\")").unwrap();
            eval(&mut c, "use(\"people\")").unwrap();
            // JSON values with an indexed "city" field (values are JSON-encoded
            // strings in the DSL; the index extracts the field from them).
            eval(&mut c, "put(\"ada\", \"{\\\"city\\\":\\\"london\\\"}\")").unwrap();
            eval(&mut c, "put(\"bob\", \"{\\\"city\\\":\\\"paris\\\"}\")").unwrap();
            eval(&mut c, "put(\"cyn\", \"{\\\"city\\\":\\\"london\\\"}\")").unwrap();
            // Define the secondary index on city.
            assert_eq!(eval(&mut c, "index_create(\"city\")").unwrap().json(), "true");
            // by_index(city, london) → ada, cyn (sorted by key).
            let rows = eval(&mut c, "by_index(\"city\",\"london\")").unwrap();
            assert_eq!(
                rows,
                Value::List(vec![Value::Str("ada".into()), Value::Str("cyn".into())])
            );
            // Different value.
            let rows2 = eval(&mut c, "by_index(\"city\",\"paris\")").unwrap();
            assert_eq!(rows2, Value::List(vec![Value::Str("bob".into())]));
            // Overwrite bob → rebuilds his row.
            eval(&mut c, "put(\"bob\", \"{\\\"city\\\":\\\"london\\\"}\")").unwrap();
            let rows3 = eval(&mut c, "by_index(\"city\",\"london\")").unwrap();
            assert_eq!(
                rows3,
                Value::List(vec![Value::Str("ada".into()), Value::Str("bob".into()), Value::Str("cyn".into())])
            );
            // Delete removes index rows.
            eval(&mut c, "del(\"ada\")").unwrap();
            let rows4 = eval(&mut c, "by_index(\"city\",\"london\")").unwrap();
            assert_eq!(
                rows4,
                Value::List(vec![Value::Str("bob".into()), Value::Str("cyn".into())])
            );
        }
        // Reopen: the index is rebuilt from the definition + current values
        // (definition replicated, index derived) and still answers.
        {
            let mut s = Store::open(&dir).unwrap();
            let mut c = ctx(&mut s);
            eval(&mut c, "use(\"people\")").unwrap();
            assert_eq!(
                eval(&mut c, "index_fields()").unwrap().json(),
                "[\"city\"]"
            );
            let rows = eval(&mut c, "by_index(\"city\",\"london\")").unwrap();
            assert_eq!(
                rows,
                Value::List(vec![Value::Str("bob".into()), Value::Str("cyn".into())])
            );
        }
    }

    #[test]
    fn remote_ql_cannot_escape_scope_or_create_ns() {
        // The HTTP /ql path runs with `remote: true` (cap-scoped): admin
        // ops must not be reachable through it. use() (scope escape) and
        // create_ns() (L1 op) must error, while data fns still work.
        let dir = tmpdir("remote");
        {
            let mut s = Store::open(&dir).unwrap();
            let mut c = ctx(&mut s);
            eval(&mut c, "create_ns(\"app\")").unwrap(); // local (REPL-like) can create
            eval(&mut c, "use(\"app\")").unwrap(); // ...and use it locally
            c.remote = true; // simulate the HTTP ql path
            // create_ns (an L1 op) is refused remotely.
            assert!(matches!(
                eval(&mut c, "create_ns(\"evil\")"),
                Err(QueryError::Type(_))
            ));
            // use() (scope escape) is refused remotely.
            assert!(matches!(
                eval(&mut c, "use(\"other\")"),
                Err(QueryError::Type(_))
            ));
        }
        // The remote caller could not create 'evil'.
        let s = Store::open(&dir).unwrap();
        assert!(s.policy("evil").is_none(), "remote create_ns must not create the ns");
        assert!(s.policy("app").is_some(), "local create_ns still allowed");
    }
}