# Honeypot Lab

A small cybersecurity lab project where I'm building and testing a honeypot to learn more about attack traffic, logging, and basic security monitoring.

The idea is to set up a controlled environment where I can expose a service, collect connection and attack data, and then analyze what happened.

This is mainly a learning project and everything is being tested in my own lab.

## What I'm trying to learn

- How honeypots work
- How attackers interact with exposed services
- What useful information can be collected from connection attempts
- How to analyze logs and identify suspicious activity
- Basic detection and monitoring
- How to document security findings

## Project structure

```text
setup/       Setup scripts and installation steps
config/      Honeypot configuration
scripts/     Scripts used for the lab
analysis/    Analysis of collected data
data/        Logs and other collected data
screenshots/ Screenshots from the lab
diagrams/    Network and lab diagrams

Current status
The honeypot is working and can simulate an SSH login service.
The lab currently:
- Accepts connections on a TCP port
- Simulates an SSH login process
- Records connection and login activity
- Records failed authentication attempts
- Detects repeated login attempts
- Generates an incident report
- Generates a timeline of the activity
The testing is currently being done locally using controlled traffic.
Lab approach
The honeypot is kept isolated from my normal network as much as possible.
The current workflow is:
1. Start the honeypot
2. Generate controlled test traffic
3. Capture and store the logs
4. Analyze the activity
5. Generate an incident report
6. Generate a timeline
7. Document interesting findings
Why I'm building this
I'm interested in cybersecurity and wanted to build something where I could practice more of the monitoring and investigation side instead of only doing CTFs.
This project should also give me a better understanding of what happens after an exposed service starts receiving suspicious traffic.

# Disclaimer

This project is for my own lab environment and learning purposes.
I only test against systems and services that I own or have permission to test.
