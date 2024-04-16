# Programmable Networks - Assignment

## Project 4 – In-network feature collection of H264 or H265 streams

Real-Time Streaming Protocol with H264 or H265 payload 

H26X:
- I frames – key frames
- P frames – refinement frames anchored to previous frames – carry changes
- (B frames – further refinement frames anchored to previous and future frames)

Goals:
- Parse I and P frames 
- Collecting per stream features like i-frame rate, p-frame rate, p-frame sizes, i-frame sizes, inter frame gaps, etc.
- Telemetry packet that can read the features and deliver it to a telemetry collector server
    - similar to postcard telemetry
    - Telemetry collector server and the telemetry packet generator can be implemented in python with scapy
