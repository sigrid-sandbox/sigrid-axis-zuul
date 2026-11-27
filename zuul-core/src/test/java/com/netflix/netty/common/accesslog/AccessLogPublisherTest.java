/*
 * Copyright 2026 Netflix, Inc.
 *
 *      Licensed under the Apache License, Version 2.0 (the "License");
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */

package com.netflix.netty.common.accesslog;

import static org.assertj.core.api.Assertions.assertThat;

import com.netflix.config.ConfigurationManager;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.apache.commons.configuration.AbstractConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AccessLogPublisherTest {
    private final AbstractConfiguration config = ConfigurationManager.getConfigInstance();

    @AfterEach
    void clearConfig() {
        config.clearProperty("zuul.access.log.uri.length.limit");
    }

    @Test
    void buildAccessLogLineIncludesExpectedFields() {
        config.setProperty("zuul.access.log.uri.length.limit", 5);
        AccessLogPublisher publisher = new AccessLogPublisher("test", (channel, request) -> "request-id");
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/abcdefghi");
        request.headers().set("host", "example.com");
        request.headers().set("user-agent", "agent");
        request.headers().set("x-forwarded-port", "8443");
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.ACCEPTED);
        response.headers().set("server", "zuul");
        response.headers().set("content-type", "text/plain");
        AccessLogPublisher.AccessLogEntry entry = new AccessLogPublisher.AccessLogEntry();
        entry.dateTime = "2026-01-02T03:04:05";
        entry.remoteIp = "10.0.0.1";
        entry.localPort = "8080";
        entry.method = "GET";
        entry.uri = "/abcd";
        entry.status = "202";
        entry.duration = "2";
        entry.responseBodySize = "1024";
        entry.requestId = "request-id";
        entry.requestBodySize = "512";
        entry.requestHeaders = request.headers();
        entry.responseHeaders = response.headers();

        String line = publisher.buildAccessLogLine(entry);
        String[] fields = line.split("\t", -1);

        assertThat(fields).hasSize(19);
        assertThat(fields[0]).isEqualTo("2026-01-02T03:04:05");
        assertThat(fields[1]).isEqualTo("10.0.0.1");
        assertThat(fields[2]).isEqualTo("8080");
        assertThat(fields[3]).isEqualTo("GET");
        assertThat(fields[4]).isEqualTo("/abcd");
        assertThat(fields[5]).isEqualTo("202");
        assertThat(fields[6]).isEqualTo("2");
        assertThat(fields[7]).isEqualTo("1024");
        assertThat(fields[8]).isEqualTo("request-id");
        assertThat(fields[9]).isEqualTo("512");
        assertThat(fields[10]).isEqualTo("\"example.com\"");
        assertThat(fields[14]).isEqualTo("\"8443\"");
        assertThat(fields[15]).isEqualTo("\"agent\"");
        assertThat(fields[16]).isEqualTo("\"zuul\"");
        assertThat(fields[18]).isEqualTo("\"text/plain\"");
    }

    @Test
    void buildAccessLogLineHandlesMissingValues() {
        AccessLogPublisher publisher = new AccessLogPublisher("test", (channel, request) -> "request-id");
        AccessLogPublisher.AccessLogEntry entry = new AccessLogPublisher.AccessLogEntry();
        entry.dateTime = "-----T-:-:-";
        entry.remoteIp = "-";
        entry.localPort = "-";
        entry.method = "-";
        entry.uri = "-";
        entry.status = "-";
        entry.duration = "-";
        entry.responseBodySize = "-";
        entry.requestId = "-";
        entry.requestBodySize = "-";

        String line = publisher.buildAccessLogLine(entry);
        String[] fields = line.split("\t", -1);

        assertThat(fields).hasSize(10);
        assertThat(fields[0]).isEqualTo("-----T-:-:-");
        assertThat(fields[1]).isEqualTo("-");
        assertThat(fields[2]).isEqualTo("-");
        assertThat(fields[3]).isEqualTo("-");
        assertThat(fields[4]).isEqualTo("-");
        assertThat(fields[5]).isEqualTo("-");
        assertThat(fields[6]).isEqualTo("-");
        assertThat(fields[7]).isEqualTo("-");
        assertThat(fields[8]).isEqualTo("-");
        assertThat(fields[9]).isEqualTo("-");
    }
}
