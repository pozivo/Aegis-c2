use serde::{Deserialize, Serialize};
use std::{env, thread, time::Duration};

#[derive(Serialize)]
struct Enrollment {
    engagement_id: String,
    hostname: String,
    os: &'static str,
    architecture: &'static str,
}

#[derive(Deserialize)]
struct EnrolledAgent {
    id: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = env::var("AEGIS_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let engagement_id = env::var("AEGIS_ENGAGEMENT_ID")?;
    let payload = Enrollment {
        engagement_id,
        hostname: hostname::get()?.to_string_lossy().into_owned(),
        os: env::consts::OS,
        architecture: env::consts::ARCH,
    };
    let enrolled: EnrolledAgent = ureq::post(&format!("{server}/v1/agents/enroll"))
        .send_json(serde_json::to_value(payload)?)?
        .into_json()?;
    loop {
        ureq::post(&format!("{server}/v1/agents/{}/heartbeat", enrolled.id)).call()?;
        thread::sleep(Duration::from_secs(30));
    }
}
