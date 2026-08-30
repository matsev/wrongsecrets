package org.owasp.wrongsecrets.canaries;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class CanaryCallbackTest {
  @Autowired private MockMvc mvc;
  @Autowired private ObjectMapper objectMapper;

  private ListAppender<ILoggingEvent> logAppender;
  private Logger controllerLogger;

  @BeforeEach
  void attachLogAppender() {
    controllerLogger = (Logger) LoggerFactory.getLogger(CanariesController.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    controllerLogger.addAppender(logAppender);
  }

  @AfterEach
  void detachLogAppender() {
    controllerLogger.detachAppender(logAppender);
  }

  @Test
  void shouldAcceptPostOfMessage() throws Exception {
    var additonalCanaryData = new AdditionalCanaryData("source", "agent", "referer", "location");
    var canaryToken = new CanaryToken("url", "memo", "channel", "time", additonalCanaryData);

    mvc.perform(
            post("/canaries/tokencallback")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(canaryToken)))
        .andExpect(status().isAccepted());
  }

  @Test
  void shouldNotLogSensitiveFields() throws Exception {
    var additionalCanaryData =
        new AdditionalCanaryData("203.0.113.5", "TestAgent/1.0", "referer", "location");
    var canaryToken =
        new CanaryToken(
            "http://canarytokens.org/manage?token=SECRETTOKEN&auth=SECRETAUTH",
            "memo",
            "channel",
            "time",
            additionalCanaryData);

    mvc.perform(
            post("/canaries/tokencallback")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(canaryToken)))
        .andExpect(status().isAccepted());

    var loggedMessages =
        logAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();

    assertThat(loggedMessages)
        .noneMatch(
            message ->
                message.contains("SECRETTOKEN")
                    || message.contains("SECRETAUTH")
                    || message.contains("203.0.113.5")
                    || message.contains("TestAgent/1.0"));
  }
}

/*
"manageUrl" : "url", "memo" : "memo", "channel" : "channel", "time" : "time", "additionalData" : { "srcIp" : "source", "useragent" : "agent", "referer" : "referer", "location" : "location"}}
 */
