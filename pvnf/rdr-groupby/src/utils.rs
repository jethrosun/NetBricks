use failure::Fallible;
use headless_chrome::{Browser, LaunchOptionsBuilder};
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use std::vec::Vec;

/// Create the browser for RDR proxy (user browsing).
///
/// FIXME: Instead of using the particular forked branch we want to eventually use the official
/// headless chrome create but set those parameters correctly here.
pub fn browser_create() -> Fallible<Browser> {
    // /usr/bin/chromedriver
    // /usr/bin/chromium-browser

    let timeout = Duration::new(1000, 0);
    let options = LaunchOptionsBuilder::default()
        .headless(true)
        .idle_browser_timeout(timeout)
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    Ok(browser)
}

/// Simple user browse.
pub fn simple_user_browse(current_browser: &Browser, hostname: &String, user: &i64) -> Fallible<(usize, u128)> {
    let now = Instant::now();
    let current_tab = match current_browser.new_tab() {
        Ok(tab) => tab,
        Err(e) => match e {
            Timeout => {
                thread::sleep(Duration::from_millis(100));
                let t = match current_browser.new_tab() {
                    Ok(tab) => tab,
                    Err(e) => {
                        println!(
                            "RDR Tab timeout after the second try for hostname: {:?} and user: {}",
                            hostname, user
                        );
                        return Ok((3, now.elapsed().as_millis()));
                    }
                };
                t
            }
            _ => {
                println!(
                    "RDR Tab failed for unknown reason hostname: {:?} and user: {}",
                    hostname, user
                );
                return Ok((2, now.elapsed().as_millis()));
            }
        },
    };

    let http_hostname = "http://".to_string() + &hostname;

    current_tab.navigate_to(&http_hostname)?;

    Ok((1, now.elapsed().as_millis()))
}

/// RDR proxy browsing scheduler.
pub fn rdr_scheduler_ng(
    pivot: &usize,
    rdr_users: &Vec<i64>,
    current_work: Vec<(u64, String, i64)>,
    browser_list: &HashMap<i64, Browser>,
) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let mut num_of_ok = 0;
    let mut num_of_err = 0;
    let mut num_of_timeout = 0;
    let mut num_of_closed = 0;
    let mut num_of_visit = 0;
    let mut elapsed_time = Vec::new();

    for (milli, url, user) in current_work.into_iter() {
        println!("User {:?}: milli: {:?} url: {:?}", user, milli, url);

        if rdr_users.contains(&user) {
            match simple_user_browse(&browser_list[&user], &url, &user) {
                Ok((val, t)) => match val {
                    // ok
                    1 => {
                        num_of_ok += 1;
                        num_of_visit += 1;
                        elapsed_time.push(t as usize);
                    }
                    // err
                    2 => {
                        num_of_err += 1;
                        num_of_visit += 1;
                        elapsed_time.push(t as usize);
                    }
                    // timeout
                    3 => {
                        num_of_timeout += 1;
                        num_of_visit += 1;
                        elapsed_time.push(t as usize);
                    }
                    _ => println!("Error: unknown user browsing error type"),
                },
                Err(e) => {
                    println!("User browsing failed for url {} with user {} :{:?}", url, user, e);
                    num_of_err += 1;
                    num_of_visit += 1;
                }
            }
        }
    }

    let total = elapsed_time.iter().sum();

    if num_of_visit > 0 {
        Some((
            num_of_ok,
            num_of_err,
            num_of_timeout,
            num_of_closed,
            elapsed_time.len(),
            total,
        ))
    } else {
        None
    }
}
