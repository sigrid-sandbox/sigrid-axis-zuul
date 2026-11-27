/*
 * Copyright 2018 Netflix, Inc.
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

import com.netflix.config.DynamicIntProperty;
import com.netflix.config.DynamicStringListProperty;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.function.BiFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessLogPublisher {
    private static final char DELIM = '\t';
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private static final List<String> LOG_REQ_HEADERS = new DynamicStringListProperty(
                    "zuul.access.log.requestheaders",
                    "host,x-forwarded-for,x-forwarded-proto,x-forwarded-host,x-forwarded-port,user-agent")
            .get();
    private static final List<String> LOG_RESP_HEADERS =
            new DynamicStringListProperty("zuul.access.log.responseheaders", "server,via,content-type").get();
    private static final DynamicIntProperty URI_LENGTH_LIMIT =
            new DynamicIntProperty("zuul.access.log.uri.length.limit", Integer.MAX_VALUE);

    private final Logger logger;
    private final BiFunction<Channel, HttpRequest, String> requestIdProvider;

    private static final Logger LOG = LoggerFactory.getLogger(AccessLogPublisher.class);

    public AccessLogPublisher(String loggerName, BiFunction<Channel, HttpRequest, String> requestIdProvider) {
        this.logger = LoggerFactory.getLogger(loggerName);
        this.requestIdProvider = requestIdProvider;
    }

    public void log(
            Channel channel,
            HttpRequest request,
            HttpResponse response,
            LocalDateTime dateTime,
            Integer localPort,
            String remoteIp,
            Long durationNs,
            Long requestBodySize,
            Long responseBodySize) {
        AccessLogEntry entry = new AccessLogEntry();
        entry.dateTime = dateTimeField(dateTime);
        entry.remoteIp = remoteIpField(remoteIp);
        entry.localPort = localPortField(localPort);
        entry.method = requestMethod(request);
        entry.uri = requestUri(request);
        entry.requestId = requestId(channel, request);
        entry.requestHeaders = request != null ? request.headers() : null;
        entry.status = responseStatus(response);
        entry.responseHeaders = response != null ? response.headers() : null;
        entry.duration = durationField(durationNs);
        entry.requestBodySize = requestBodySizeField(requestBodySize);
        entry.responseBodySize = responseBodySizeField(responseBodySize);

        String access = buildAccessLogLine(entry);
        logger.info(access);
        LOG.debug(access);
    }

    String buildAccessLogLine(AccessLogEntry entry) {
        StringBuilder builder = new StringBuilder(512);

        appendBaseFields(builder, entry);
        appendLogHeaders(builder, entry);
        return builder.toString();
    }

    private void appendBaseFields(StringBuilder builder, AccessLogEntry entry) {
        appendField(builder, entry.dateTime);
        appendField(builder, entry.remoteIp);
        appendField(builder, entry.localPort);
        appendField(builder, entry.method);
        appendField(builder, entry.uri);
        appendField(builder, entry.status);
        appendField(builder, entry.duration);
        appendField(builder, entry.responseBodySize);
        appendField(builder, entry.requestId);
        builder.append(entry.requestBodySize);
    }

    private void appendLogHeaders(StringBuilder builder, AccessLogEntry entry) {
        if (entry.requestHeaders != null) {
            appendRequestHeaders(builder, entry.requestHeaders);
        }

        if (entry.responseHeaders != null) {
            appendResponseHeaders(builder, entry.responseHeaders);
        }
    }

    private String dateTimeField(LocalDateTime dateTime) {
        return dateTime != null ? dateTime.format(DATE_TIME_FORMATTER) : "-----T-:-:-";
    }

    private String remoteIpField(String remoteIp) {
        return (remoteIp != null && !remoteIp.isEmpty()) ? remoteIp : "-";
    }

    private String localPortField(Integer localPort) {
        return localPort != null ? localPort.toString() : "-";
    }

    private String requestMethod(HttpRequest request) {
        return request != null ? request.method().toString().toUpperCase(Locale.ROOT) : "-";
    }

    private String requestUri(HttpRequest request) {
        String uri = request != null ? request.uri() : "-";
        return uri.length() > URI_LENGTH_LIMIT.get() ? uri.substring(0, URI_LENGTH_LIMIT.get()) : uri;
    }

    private String responseStatus(HttpResponse response) {
        return response != null ? String.valueOf(response.status().code()) : "-";
    }

    private String requestId(Channel channel, HttpRequest request) {
        try {
            String requestId = requestIdProvider.apply(channel, request);
            return requestId != null ? requestId : "-";
        } catch (Exception ex) {
            LOG.error("requestIdProvider failed in AccessLogPublisher", ex);
            return "-";
        }
    }

    private String durationField(Long durationNs) {
        return (durationNs != null && durationNs > 0) ? String.valueOf(durationNs / 1000) : "-";
    }

    private String requestBodySizeField(Long requestBodySize) {
        return (requestBodySize != null && requestBodySize > 0) ? requestBodySize.toString() : "-";
    }

    private String responseBodySizeField(Long responseBodySize) {
        return (responseBodySize != null && responseBodySize > 0) ? responseBodySize.toString() : "-";
    }

    private void appendField(StringBuilder builder, String value) {
        builder.append(value).append(DELIM);
    }

    private void appendRequestHeaders(StringBuilder builder, HttpHeaders headers) {
        for (String headerName : LOG_REQ_HEADERS) {
            builder.append(DELIM).append('\"').append(headerAsString(headers, headerName)).append('\"');
        }
    }

    private void appendResponseHeaders(StringBuilder builder, HttpHeaders headers) {
        for (String headerName : LOG_RESP_HEADERS) {
            builder.append(DELIM).append('\"').append(headerAsString(headers, headerName)).append('\"');
        }
    }

    String headerAsString(HttpHeaders headers, String headerName) {
        List<String> values = headers.getAll(headerName);
        return values.isEmpty() ? "-" : String.join(",", values);
    }

    static final class AccessLogEntry {
        String dateTime;
        String remoteIp;
        String localPort;
        String method;
        String uri;
        String status;
        String duration;
        String responseBodySize;
        String requestId;
        String requestBodySize;
        HttpHeaders requestHeaders;
        HttpHeaders responseHeaders;
    }
}
