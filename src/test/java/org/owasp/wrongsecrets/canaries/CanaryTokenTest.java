package org.owasp.wrongsecrets.canaries;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CanaryTokenTest {

  @Test
  void toStringShouldRedactSensitiveFieldsButKeepSafeOnes() {
    var additionalData =
        new AdditionalCanaryData("203.0.113.5", "TestAgent/1.0", "https://referer.example", "loc");
    var canaryToken =
        new CanaryToken(
            "http://canarytokens.org/manage?token=SECRETTOKEN&auth=SECRETAUTH",
            "memo",
            "channel",
            "time",
            additionalData);

    var result = canaryToken.toString();

    assertThat(result).contains("memo", "channel", "time");
    assertThat(result).doesNotContain("SECRETTOKEN", "SECRETAUTH", "203.0.113.5", "TestAgent/1.0");
  }
}
