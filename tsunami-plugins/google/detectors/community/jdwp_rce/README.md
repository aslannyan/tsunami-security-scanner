# Detector for Exposed Java Debug Wire Protocol (JDWP) Services

## Detector Overview

This Tsunami detector identifies publicly exposed Java Debug Wire Protocol (JDWP) services. JDWP is a protocol used for debugging Java applications. When exposed to untrusted networks, JDWP can often allow unauthenticated Remote Code Execution (RCE) due to its design.

The detector works by attempting a JDWP handshake with a discovered open TCP port. It sends the ASCII string "JDWP-Handshake" and expects the service to reply with the exact same string. A successful handshake confirms an active and exposed JDWP service.

**Vulnerability Details:**

*   **ID:** JDWP_RCE
*   **Severity:** CRITICAL
*   **Recommendation:** Either disable the JDWP service, limit its accessibility to localhost, or configure a firewall to restrict exposure to only trusted entities. For further guidance, refer to [go/fixing-jdwp](http://go/fixing-jdwp).

## Automated Unit Testing

The detector includes unit tests to verify its logic against mock JDWP services. These tests ensure the detector correctly identifies vulnerable and non-vulnerable endpoints.

**Prerequisites:**

*   Python 3.7+
*   `unittest` and `asyncio` Python libraries (standard libraries)

**Running the Unit Tests:**

1.  Navigate to the plugin's testing directory:
    ```bash
    cd tsunami-plugins/google/detectors/community/jdwp_rce/testing/
    ```

2.  Run the Python test script:
    ```bash
    python3 detector_test.py
    ```
    The script will output the results of the tests, indicating success or failure for each test case (vulnerable, non-vulnerable with wrong response, non-vulnerable with no response).

## Manual Verification Procedure

This section describes how to manually build the detector, build the test Docker container, and run the Tsunami scanner against the container to verify the detector's functionality.

**Prerequisites:**

*   Docker installed and running.
*   Java Development Kit (JDK) 11 or compatible (for building the plugin).
*   Gradle (for building the plugin).
*   A Tsunami scanner environment.

**Steps:**

1.  **Build the JDWP RCE Detector Plugin:**
    Navigate to the plugin's root directory and build the fat JAR:
    ```bash
    cd tsunami-plugins/google/detectors/community/jdwp_rce/
    gradle shadowJar
    ```
    This will create the plugin JAR file in `build/libs/jdwp_rce-0.1.jar`.

2.  **Build the Test Docker Image:**
    Navigate to the testing directory and build the Docker image:
    ```bash
    cd testing/
    docker build -t jdwp-test-target .
    ```

3.  **Run the Docker Container:**
    Run the container, exposing the JDWP port (5005) to the host:
    ```bash
    docker run -d -p 5005:5005 --name jdwp_container jdwp-test-target
    ```
    You can verify the container is running and the Java application has started:
    ```bash
    docker logs jdwp_container
    ```
    You should see output like "Hello World JDWP Test Application Running...".

4.  **Run Tsunami Scanner against the Docker Container:**
    Execute the Tsunami scanner, pointing it to the IP address of your Docker host and the exposed port. Ensure the built plugin JAR is in Tsunami's plugin directory.

    *Example Tsunami command (replace placeholders as needed):*
    ```bash
    java -cp "/path/to/tsunami/target/tsunami-main-0.0.14-SNAPSHOT-cli.jar:/path/to/tsunami/plugins/*"          com.google.tsunami.main.cli.TsunamiCli          --ip-v4-target YOUR_DOCKER_HOST_IP          --scan-results-local-output-format JSON          --scan-results-local-output-filename /tmp/tsunami_jdwp_results.json          --plugins jdwp_rce-0.1.jar          --port-ranges 5005
    ```
    *Note: `YOUR_DOCKER_HOST_IP` is typically `127.0.0.1` if running Docker locally on Linux. For Docker Desktop on Mac/Windows, it might be different; you may need to use `host.docker.internal` or the IP of your machine.*
    *Ensure the `jdwp_rce-0.1.jar` (or the full path to it) is correctly specified or present in a directory scanned by Tsunami for plugins.*

5.  **Verify Detection Report:**
    Check the Tsunami output or the specified JSON results file (`/tmp/tsunami_jdwp_results.json`). You should find a vulnerability report for the exposed JDWP service on port 5005. The report should indicate `VULNERABILITY_VERIFIED` and include the details specified in the `JdwpRceDetector.java` file.

6.  **Clean Up:**
    Stop and remove the Docker container:
    ```bash
    docker stop jdwp_container
    docker rm jdwp_container
    ```
    Optionally, remove the Docker image:
    ```bash
    docker rmi jdwp-test-target
    ```

This procedure allows a reviewer to confirm that the detector correctly identifies the JDWP service running in the Docker container.
