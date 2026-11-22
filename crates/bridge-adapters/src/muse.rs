use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Read};

const EXPECTED_CLI: &str = "1.4.24-R9131.1";
const MAX_TOTAL: u64 = 16 * 1024 * 1024;
const MAX_LINE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuseRunEvidence {
    pub cli_version: String,
    pub session_id: String,
    pub model_id: String,
    pub run_id: String,
    pub subscription_source: String,
    pub window_used_percent: u8,
    pub weekly_used_percent: u8,
    pub event_count: u64,
    pub first_output_at_us: Option<u64>,
    pub completed_at_us: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuseEventError {
    CliVersionMismatch,
    SessionMismatch,
    ModelMismatch,
    MalformedEvent(&'static str),
    UnsupportedVersion(&'static str),
    MissingEvent(&'static str),
    DuplicateEvent(&'static str),
    RunFailed(&'static str),
}

impl std::fmt::Display for MuseEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CliVersionMismatch => write!(f, "cli-version-mismatch"),
            Self::SessionMismatch => write!(f, "session-mismatch"),
            Self::ModelMismatch => write!(f, "model-mismatch"),
            Self::MalformedEvent(c) => write!(f, "malformed-event:{c}"),
            Self::UnsupportedVersion(c) => write!(f, "unsupported-version:{c}"),
            Self::MissingEvent(c) => write!(f, "missing-event:{c}"),
            Self::DuplicateEvent(c) => write!(f, "duplicate-event:{c}"),
            Self::RunFailed(c) => write!(f, "run-failed:{c}"),
        }
    }
}

impl std::error::Error for MuseEventError {}
impl From<std::io::Error> for MuseEventError {
    fn from(_: std::io::Error) -> Self {
        Self::MalformedEvent("io")
    }
}

use MuseEventError::*;

struct EventState {
    run: Option<String>,
    configured: bool,
    usage_seen: bool,
    completed: bool,
    w: u8,
    weekly_percent: u8,
    first: Option<u64>,
    done_at: Option<u64>,
    n: u64,
}

fn step(
    state: &mut EventState,
    v: &Value,
    expected_session: &str,
    expected_model: &str,
) -> Result<(), MuseEventError> {
    let g = |p: &str| v.pointer(p);
    if g("/schema_version").and_then(|x| x.as_u64()) != Some(1) {
        return Err(UnsupportedVersion("schema"));
    }
    if g("/payload_schema_version").and_then(|x| x.as_u64()) != Some(1) {
        return Err(UnsupportedVersion("payload"));
    }
    let pt = g("/payload_type")
        .and_then(|x| x.as_str())
        .ok_or(MalformedEvent("payload-type"))?;
    if g("/stream/id").and_then(|x| x.as_str()) != Some(expected_session) {
        return Err(SessionMismatch);
    }
    let cmd = g("/payload/command_id")
        .and_then(|x| x.as_str())
        .ok_or(MalformedEvent("run-link"))?;
    let rid = g("/payload/run_stream/id")
        .and_then(|x| x.as_str())
        .ok_or(MalformedEvent("run-link"))?;
    if cmd != rid {
        return Err(MalformedEvent("run-link"));
    }
    match &state.run {
        Some(r) if r != cmd => return Err(MalformedEvent("run-link")),
        Some(_) => {}
        None => state.run = Some(cmd.to_string()),
    }
    let at = g("/recorded_at").and_then(|x| x.as_u64());
    match pt {
        "run.model.configured" => {
            if state.configured {
                return Err(DuplicateEvent("configured"));
            }
            if g("/payload/provider_id").and_then(|x| x.as_str()) != Some("meta") {
                return Err(MalformedEvent("provider"));
            }
            if g("/payload/model_id").and_then(|x| x.as_str()) != Some(expected_model) {
                return Err(ModelMismatch);
            }
            state.configured = true;
        }
        "run.usage" => {
            if state.usage_seen {
                return Err(DuplicateEvent("usage"));
            }
            let ms = g("/payload/models")
                .and_then(|x| x.as_array())
                .ok_or(MalformedEvent("models"))?;
            if ms.is_empty() {
                return Err(MalformedEvent("models"));
            }
            for m in ms {
                if m.pointer("/model").and_then(|x| x.as_str()) != Some(expected_model) {
                    return Err(ModelMismatch);
                }
            }
            if g("/payload/completed_calls")
                .and_then(|x| x.as_u64())
                .unwrap_or(0)
                == 0
            {
                return Err(RunFailed("calls"));
            }
            if g("/payload/failed_calls").and_then(Value::as_u64) != Some(0) {
                return Err(RunFailed("failed-calls"));
            }
            if g("/payload/cancelled_calls").and_then(Value::as_u64) != Some(0) {
                return Err(RunFailed("cancelled"));
            }
            if g("/payload/children_included")
                .and_then(|x| x.as_bool())
                .unwrap_or(true)
            {
                return Err(RunFailed("children"));
            }
            if g("/payload/allowance/source").and_then(|x| x.as_str()) != Some("stream") {
                return Err(MissingEvent("subscription"));
            }
            let w = g("/payload/allowance/window/used_percent")
                .and_then(|x| x.as_u64())
                .ok_or(MalformedEvent("quota"))?;
            let weekly_percent = g("/payload/allowance/weekly/used_percent")
                .and_then(|x| x.as_u64())
                .ok_or(MalformedEvent("quota"))?;
            if w > 100 || weekly_percent > 100 {
                return Err(MalformedEvent("quota-range"));
            }
            state.w = w as u8;
            state.weekly_percent = weekly_percent as u8;
            state.usage_seen = true;
        }
        "run.output.delta" => {
            if state.first.is_none() {
                state.first = at;
            }
        }
        "run.terminal.completed" => {
            if state.completed {
                return Err(DuplicateEvent("terminal"));
            }
            if g("/payload/terminal").and_then(Value::as_str) != Some("completed") {
                return Err(RunFailed("terminal-status"));
            }
            if g("/payload/text")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(MalformedEvent("terminal-text"));
            }
            state.completed = true;
            state.done_at = at;
        }
        t if t.starts_with("run.terminal.") => return Err(RunFailed("terminal-type")),
        _ => {}
    }
    Ok(())
}

fn observe_line(
    raw: &[u8],
    state: &mut EventState,
    expected_session: &str,
    expected_model: &str,
) -> Result<(), MuseEventError> {
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let event: Value = serde_json::from_slice(raw).map_err(|_| MalformedEvent("json"))?;
    let kind = event
        .get("payload_type")
        .and_then(Value::as_str)
        .ok_or(MalformedEvent("payload-type"))?;
    state.n += 1;
    if matches!(
        kind,
        "run.model.configured" | "run.usage" | "run.output.delta"
    ) || kind.starts_with("run.terminal.")
    {
        step(state, &event, expected_session, expected_model)?;
    }
    Ok(())
}

pub fn inspect_muse_events<R: BufRead>(
    reader: R,
    cli_version: &str,
    expected_session: &str,
    expected_model: &str,
    exit_code: i32,
) -> Result<MuseRunEvidence, MuseEventError> {
    if cli_version != EXPECTED_CLI {
        return Err(CliVersionMismatch);
    }
    if uuid::Uuid::parse_str(expected_session).is_err() {
        return Err(SessionMismatch);
    }
    if expected_model.is_empty() {
        return Err(ModelMismatch);
    }
    let mut limited = reader.take(MAX_TOTAL + 1);
    let mut state = EventState {
        run: None,
        configured: false,
        usage_seen: false,
        completed: false,
        w: 0,
        weekly_percent: 0,
        first: None,
        done_at: None,
        n: 0,
    };
    let mut line = Vec::new();
    let mut total = 0;
    loop {
        line.clear();
        let read = (&mut limited)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_TOTAL {
            return Err(MalformedEvent("total-too-large"));
        }
        if read > MAX_LINE {
            return Err(MalformedEvent("line-too-long"));
        }
        observe_line(&line, &mut state, expected_session, expected_model)?;
    }
    if !state.configured {
        return Err(MissingEvent("configured"));
    }
    if !state.usage_seen {
        return Err(MissingEvent("usage"));
    }
    if !state.completed {
        return Err(MissingEvent("terminal"));
    }
    if exit_code != 0 {
        return Err(RunFailed("exit-code"));
    }
    Ok(MuseRunEvidence {
        cli_version: EXPECTED_CLI.to_string(),
        session_id: expected_session.to_string(),
        model_id: expected_model.to_string(),
        run_id: state.run.ok_or(MissingEvent("configured"))?,
        subscription_source: "stream".to_string(),
        window_used_percent: state.w,
        weekly_used_percent: state.weekly_percent,
        event_count: state.n,
        first_output_at_us: state.first,
        completed_at_us: state.done_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    const SS: &str = "123e4567-e89b-12d3-a456-426614174000";
    const M: &str = "muse-spark-1.3-contributor";
    const CV: &str = "1.4.24-R9131.1";
    const T: [&str; 4] = [
        r#"{"schema_version":1,"stream":{"kind":"session","id":"SESSION"},"recorded_at":100,"payload_type":"run.model.configured","payload_schema_version":1,"payload":{"command_id":"RUN","run_stream":{"kind":"run","id":"RUN"},"provider_id":"meta","model_id":"muse-spark-1.3-contributor"}}"#,
        r#"{"schema_version":1,"stream":{"kind":"session","id":"SESSION"},"recorded_at":101,"payload_type":"run.output.delta","payload_schema_version":1,"payload":{"command_id":"RUN","run_stream":{"kind":"run","id":"RUN"},"text":"text"}}"#,
        r#"{"schema_version":1,"stream":{"kind":"exec.usage","id":"SESSION"},"recorded_at":102,"payload_type":"run.usage","payload_schema_version":1,"payload":{"command_id":"RUN","run_stream":{"kind":"run","id":"RUN"},"models":[{"model":"muse-spark-1.3-contributor","calls":1}],"calls":1,"completed_calls":1,"failed_calls":0,"cancelled_calls":0,"children_included":false,"allowance":{"window":{"used_percent":20},"weekly":{"used_percent":84},"source":"stream"}}}"#,
        r#"{"schema_version":1,"stream":{"kind":"session","id":"SESSION"},"recorded_at":103,"payload_type":"run.terminal.completed","payload_schema_version":1,"payload":{"command_id":"RUN","run_stream":{"kind":"run","id":"RUN"},"terminal":"completed","text":"example result","reason":null}}"#,
    ];
    fn good() -> Vec<String> {
        T.iter().map(|s| s.replace("SESSION", SS)).collect()
    }
    fn run(v: &[String], exit: i32, ss: &str, m: &str) -> Result<MuseRunEvidence, MuseEventError> {
        inspect_muse_events(Cursor::new(v.join("\n").into_bytes()), CV, ss, m, exit)
    }
    #[test]
    fn positive() {
        let e = run(&good(), 0, SS, M).unwrap();
        assert_eq!(e.run_id, "RUN");
        assert_eq!((e.window_used_percent, e.weekly_used_percent), (20, 84));
        assert_eq!(e.event_count, 4);
        assert_eq!(
            (e.first_output_at_us, e.completed_at_us),
            (Some(101), Some(103))
        );
        assert_eq!(e.subscription_source, "stream");
    }
    #[test]
    fn wrong_session_model() {
        let g = good();
        let mut w = g.clone();
        w[1] = w[1].replace(SS, "123e4567-e89b-12d3-a456-426614174001");
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), SessionMismatch);
        let mut w = g.clone();
        w[2] = w[2].replace(M, "other-model");
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), ModelMismatch);
        let mut w = g.clone();
        w[0] = w[0].replace(M, "other-model");
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), ModelMismatch);
    }
    #[test]
    fn missing_quota_malformed_failed() {
        let g = good();
        let w: Vec<String> = vec![g[0].clone(), g[1].clone(), g[3].clone()];
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), MissingEvent("usage"));
        let mut w = g.clone();
        w[2] = w[2].replace(r#""source":"stream""#, r#""source":"api""#);
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), MissingEvent("subscription"));
        let mut w = g.clone();
        w[2] = w[2].replace(r#""used_percent":84"#, r#""used_percent":120"#);
        assert_eq!(
            run(&w, 0, SS, M).unwrap_err(),
            MalformedEvent("quota-range")
        );
        let mut w = g.clone();
        w[0] = w[0].replacen(
            r#""payload_schema_version":1"#,
            r#""payload_schema_version":2"#,
            1,
        );
        assert_eq!(
            run(&w, 0, SS, M).unwrap_err(),
            UnsupportedVersion("payload")
        );
        let mut w = g.clone();
        w[3] = w[3].replace("run.terminal.completed", "run.terminal.failed");
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), RunFailed("terminal-type"));
        assert_eq!(run(&g, 1, SS, M).unwrap_err(), RunFailed("exit-code"));
        let mut w = g.clone();
        w.push(g[0].clone());
        assert_eq!(run(&w, 0, SS, M).unwrap_err(), DuplicateEvent("configured"));
    }
}
