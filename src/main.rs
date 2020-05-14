use rustsec::{lockfile::Lockfile, Database};
use std::io::Read;
use std::str::FromStr;

fn main() {
    let _output = envmnt::load_file(".env");

    if envmnt::exists("SENTRY_DSN") {
        println!("{}", envmnt::get_or_panic("SENTRY_DSN"));
        let _guard = sentry::init(envmnt::get_or_panic("SENTRY_DSN"));
    } else {
        println!("Sentry not configured");
    }
    let db = Database::fetch().unwrap();

    for source in envmnt::get_or_panic("SCAN_SOURCES").split(",") {
        println!("Reading {:?}", source);
        let mut resp = reqwest::blocking::get(source).unwrap();
        assert!(resp.status().is_success());

        let mut content = String::new();
        let _res = resp.read_to_string(&mut content);
        let lockfile = Lockfile::from_str(&content).unwrap();
        let vulns = db.vulnerabilities(&lockfile);
        if vulns.is_empty() {
            println!("No vulnerabilities in {}", source);
        } else {
            println!("Found vulnerabilities in {}", source);
            for v in &vulns {
                let name = &v.package.name;
                let id = &v.advisory.id;
                let date = &v.advisory.date;
                sentry::with_scope(
                    |scope| {
                        scope.set_level(Some(sentry::Level::Error));
                        scope.set_tag("id", &id.as_ref());
                        scope.set_tag("date", &date.as_ref());
                        scope.set_tag("source", &source);
                    },
                    || {
                        sentry::capture_message(name.as_ref(), sentry::Level::Error);
                    },
                );
            }
        }
    }
}
