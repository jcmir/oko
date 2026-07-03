use std::process::Command;

fn main() {
    let output = Command::new("rustc").arg("--version").output();
    match output {
        Ok(out) => {
            println!("Success: {}", String::from_utf8_lossy(&out.stdout));
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
