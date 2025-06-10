package com.google.tsunami.plugins.detectors.jdwp;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
 Simport com.google.tsunami.plugin.annotations.ForPort;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Instant;
import javax.inject.Inject;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JdwpRceDetector",
    version = "0.1",
    description = "Detects publicly exposed Java Debug Wire Protocol (JDWP) services.",
    author = "Google Inc.",
    bootstrapModule = JdwpRceDetectorBootstrapModule.class)
@ForPort // JDWP can run on any port, so we don't specify one.
public final class JdwpRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String JDWP_HANDSHAKE_REQUEST = "JDWP-Handshake";
  private static final String JDWP_HANDSHAKE_RESPONSE = "JDWP-Handshake";
  private static final int SOCKET_TIMEOUT_MS = 5000; // 5 seconds

  @Inject
  public JdwpRceDetector() {}

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("JdwpRceDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isTcp)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String host = networkService.getNetworkEndpoint().getIpAddress().getAddress();
    int port = networkService.getNetworkEndpoint().getPort().getPortNumber();
    InetSocketAddress socketAddress = new InetSocketAddress(host, port);

    try (Socket socket = new Socket()) {
      socket.setSoTimeout(SOCKET_TIMEOUT_MS);
      socket.connect(socketAddress, SOCKET_TIMEOUT_MS);

      try (OutputStream outputStream = socket.getOutputStream();
          InputStream inputStream = socket.getInputStream()) {
        outputStream.write(JDWP_HANDSHAKE_REQUEST.getBytes("ASCII"));
        outputStream.flush();

        byte[] responseBytes = new byte[JDWP_HANDSHAKE_RESPONSE.length()];
        int bytesRead = inputStream.read(responseBytes);

        if (bytesRead == JDWP_HANDSHAKE_RESPONSE.length()) {
          String response = new String(responseBytes, "ASCII");
          if (JDWP_HANDSHAKE_RESPONSE.equals(response)) {
            return true;
          }
        }
      }
    } catch (IOException e) {
      logger.atFine().withCause(e).log(
          "Failed to connect or perform JDWP handshake with %s:%d.", host, port);
      return false;
    }
    return false;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("JDWP_RCE"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Exposed Java Debug Wire Protocol (JDWP) Service")
                .setDescription(
                    "The Java Debug Wire Protocol (JDWP) service is publicly exposed. This service, by design, "
                        + "often allows unauthenticated remote code execution. A successful JDWP handshake "
                        + "was performed with the service, confirming an active JDWP service.")
                .setRecommendation(
                    "Either disable the service, limit it to localhost or configure a firewall to limit exposure. "
                        + "For more information, see: go/fixing-jdwp")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    String.format(
                                        "Successfully performed JDWP handshake with the service at %s.",
                                        toUriAuthority(vulnerableNetworkService.getNetworkEndpoint()))))))
        .build();
  }
}
