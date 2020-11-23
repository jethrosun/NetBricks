use failure::Fallible;
use headless_chrome::{Browser, LaunchOptionsBuilder};
use std::collections::HashMap;

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
    // let tab = browser.wait_for_initial_tab()?;
    // tab.set_default_timeout(std::time::Duration::from_secs(100));

    // println!("Browser created",);
    Ok(browser)
}

/// Simple user browse.
pub fn simple_user_browse(current_browser: &Browser, hostname: &str, _user: &i64) -> Fallible<(usize, u128)> {
    let now = Instant::now();
    let tabs = current_browser.get_tabs().lock().unwrap();
    let current_tab = tabs.iter().next().unwrap();
    let http_hostname = "http://".to_string() + &hostname;

    current_tab.navigate_to(&http_hostname)?;

    Ok((1, now.elapsed().as_millis()))
}

/// RDR proxy browsing scheduler.
pub fn rdr_scheduler_ng(
    _pivot: &usize,
    rdr_users: &[i64],
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
                Err(e) => match e {
                    // FIXME: match everything???
                    ConnectionClosed => {
                        num_of_closed += 1;
                        num_of_visit += 1;
                    }
                    _ => {
                        println!("User browsing failed for url {} with user {} :{:?}", url, user, e);
                        num_of_err += 1;
                        num_of_visit += 1;
                    }
                },
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
