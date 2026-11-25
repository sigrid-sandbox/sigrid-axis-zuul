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

package com.netflix.zuul.netty.server.ssl;

import com.google.common.annotations.VisibleForTesting;
import com.netflix.config.DynamicBooleanProperty;
import com.netflix.netty.common.SourceAddressChannelHandler;
import com.netflix.netty.common.ssl.SslHandshakeInfo;
import com.netflix.spectator.api.NoopRegistry;
import com.netflix.spectator.api.Registry;
import com.netflix.spectator.api.Tag;
import com.netflix.zuul.netty.ChannelUtils;
import com.netflix.zuul.netty.server.psk.ClientPSKIdentityInfo;
import com.netflix.zuul.netty.server.psk.TlsPskHandler;
import com.netflix.zuul.netty.server.psk.ZuulPskServer;
import com.netflix.zuul.passport.CurrentPassport;
import com.netflix.zuul.passport.PassportState;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SniCompletionEvent;
import io.netty.handler.ssl.SslCloseCompletionEvent;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.util.AttributeKey;
import java.nio.channels.ClosedChannelException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores info about the client and server's SSL certificates in the context, after a successful handshake.
 * <p>
 * User: michaels@netflix.com Date: 3/29/16 Time: 10:48 AM
 */
public class SslHandshakeInfoHandler extends ChannelInboundHandlerAdapter {

    public static final AttributeKey<SslHandshakeInfo> ATTR_SSL_INFO = AttributeKey.newInstance("_ssl_handshake_info");

    // optionally set by an outbound handler that parses the TLS ServerHello key_share extension
    public static final AttributeKey<String> ATTR_SSL_NAMED_GROUP = AttributeKey.newInstance("_ssl_named_group");

    private static final Logger logger = LoggerFactory.getLogger(SslHandshakeInfoHandler.class);

    // extracts reason string from SSL errors formatted in the open ssl style
    // error:[error code]:[library name]:OPENSSL_internal:[reason string]
    // see https://github.com/google/boringssl/blob/d206f3db6ac2b74e8949ddd9947b94a5424d6a1d/include/openssl/err.h#L231
    private static final Pattern OPEN_SSL_PATTERN = Pattern.compile("OPENSSL_internal:(.+)");

    static DynamicBooleanProperty SNI_LOGGING_ENABLED =
            new DynamicBooleanProperty("zuul.ssl.handshake.snilogging.enabled", false);

    private final Registry spectatorRegistry;
    private final boolean isSSlFromIntermediary;
    private final String listenerName;

    public SslHandshakeInfoHandler(
            @NonNull Registry spectatorRegistry, boolean isSSlFromIntermediary, @NonNull String listenerName) {
        this.spectatorRegistry = spectatorRegistry;
        this.isSSlFromIntermediary = isSSlFromIntermediary;
        this.listenerName = listenerName;
    }

    @VisibleForTesting
    SslHandshakeInfoHandler() {
        spectatorRegistry = new NoopRegistry();
        isSSlFromIntermediary = false;
        listenerName = "unknown";
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SslHandshakeCompletionEvent sslEvent) {
            handleSslHandshakeEvent(ctx, sslEvent);
            super.userEventTriggered(ctx, evt);
            return;
        }
        if (evt instanceof SslCloseCompletionEvent) {
            // TODO - increment a separate metric for this event?
            super.userEventTriggered(ctx, evt);
            return;
        }
        if (evt instanceof SniCompletionEvent sniCompletionEvent) {
            handleSniCompletionEvent(sniCompletionEvent, evt);
        }
        super.userEventTriggered(ctx, evt);
    }

    private void handleSniCompletionEvent(SniCompletionEvent sniCompletionEvent, Object evt) {
        logger.debug("SNI Parsing Complete: {}", evt);
        if (sniCompletionEvent.isSuccess()) {
            spectatorRegistry.counter("zuul.sni.parse.success").increment();
            return;
        }

        Throwable cause = sniCompletionEvent.cause();
        spectatorRegistry
                .counter("zuul.sni.parse.failure", "cause", cause != null ? cause.getMessage() : "UNKNOWN")
                .increment();
    }

    private void handleSslHandshakeEvent(ChannelHandlerContext ctx, SslHandshakeCompletionEvent sslEvent) {
        try {
            if (sslEvent.isSuccess()) {
                handleSuccessfulSslHandshake(ctx, sslEvent);
            } else {
                handleFailedSslHandshake(ctx, sslEvent);
            }
        } catch (Throwable e) {
            logger.warn("Error getting the SSL handshake info.", e);
        } finally {
            // Now remove this handler from the pipeline as no longer needed once the ssl handshake has completed.
            ctx.pipeline().remove(this);
        }
    }

    private void handleSuccessfulSslHandshake(ChannelHandlerContext ctx, SslHandshakeCompletionEvent sslEvent)
            throws Exception {
        CurrentPassport.fromChannel(ctx.channel()).add(PassportState.SERVER_CH_SSL_HANDSHAKE_COMPLETE);

        SSLSession session = getSSLSession(ctx);
        if (session == null) {
            logger.warn("Error getting the SSL handshake info. SSLSession is null");
            return;
        }

        SslHandshakeInfo info = buildSuccessfulSslHandshakeInfo(ctx, session);
        ctx.channel().attr(ATTR_SSL_INFO).set(info);

        incrementCounters(sslEvent, info);
        logger.debug("Successful SSL Handshake: {}", info);
    }

    private SslHandshakeInfo buildSuccessfulSslHandshakeInfo(ChannelHandlerContext ctx, SSLSession session)
            throws Exception {
        ClientAuth clientAuth = whichClientAuthEnum(ctx);
        return SslHandshakeInfo.builder()
                .requestedSni(getRequestedSni(session))
                .isOfIntermediary(isSSlFromIntermediary)
                .protocol(session.getProtocol())
                .cipherSuite(session.getCipherSuite())
                .namedGroup(ctx.channel().attr(ATTR_SSL_NAMED_GROUP).get())
                .clientAuthRequirement(clientAuth)
                .serverCertificate(getServerCertificate(session))
                .clientCertificate(getPeerCertificate(session, clientAuth))
                .usingExternalPSK(isTlsHandshakeUsingExternalPsk(ctx))
                .clientPSKIdentityInfo(getClientPskIdentityInfo(ctx))
                .build();
    }

    private void handleFailedSslHandshake(ChannelHandlerContext ctx, SslHandshakeCompletionEvent sslEvent) {
        if (shouldSkipFailedHandshakeLogging(ctx, sslEvent.cause())) {
            return;
        }

        logGenericSslHandshakeFailure(ctx, sslEvent);
        incrementCounters(sslEvent, buildFailedHandshakeInfo(ctx));
    }

    private boolean shouldSkipFailedHandshakeLogging(ChannelHandlerContext ctx, Throwable cause) {
        if (isClosedBeforeHandshake(ctx, cause)) {
            return true;
        }
        if (isHandshakeTimeout(ctx, cause)) {
            return true;
        }
        return isTlsControlFrameFailure(ctx, cause);
    }

    private boolean isClosedBeforeHandshake(ChannelHandlerContext ctx, Throwable cause) {
        PassportState passportState = CurrentPassport.fromChannel(ctx.channel()).getState();
        if (!(cause instanceof ClosedChannelException)
                || (passportState != PassportState.SERVER_CH_INACTIVE
                        && passportState != PassportState.SERVER_CH_IDLE_TIMEOUT)) {
            return false;
        }
        logger.debug(
                "Client closed connection or it idle timed-out without doing an ssl handshake. ,"
                        + " client_ip = {}, channel_info = {}",
                getClientIp(ctx),
                ChannelUtils.channelInfoForLogging(ctx.channel()));
        return true;
    }

    private boolean isHandshakeTimeout(ChannelHandlerContext ctx, Throwable cause) {
        if (!(cause instanceof SSLException) || !cause.getMessage().contains("handshake timed out")) {
            return false;
        }
        logger.debug(
                "Client timed-out doing the ssl handshake. , client_ip = {}, channel_info = {}",
                getClientIp(ctx),
                ChannelUtils.channelInfoForLogging(ctx.channel()));
        return true;
    }

    private boolean isTlsControlFrameFailure(ChannelHandlerContext ctx, Throwable cause) {
        if (!(cause instanceof SSLException) || !cause.getMessage().contains("failure when writing TLS control frames")) {
            return false;
        }
        logger.debug(
                "Client terminated handshake early., client_ip = {}, channel_info = {}",
                getClientIp(ctx),
                ChannelUtils.channelInfoForLogging(ctx.channel()));
        return true;
    }

    private String getClientIp(ChannelHandlerContext ctx) {
        return ctx.channel()
                .attr(SourceAddressChannelHandler.ATTR_SOURCE_ADDRESS)
                .get();
    }

    private void logGenericSslHandshakeFailure(ChannelHandlerContext ctx, SslHandshakeCompletionEvent sslEvent) {
        if (!logger.isDebugEnabled()) {
            return;
        }
        if (sslEvent.cause() instanceof ClosedChannelException) {
            logUnsuccessfulHandshakeWithoutCause(ctx, sslEvent);
            return;
        }
        logUnsuccessfulHandshakeWithCause(ctx, sslEvent);
    }

    private void logUnsuccessfulHandshakeWithoutCause(ChannelHandlerContext ctx, SslHandshakeCompletionEvent sslEvent) {
        logger.debug(
                "Unsuccessful SSL Handshake: {}, client_ip = {}, channel_info = {}, error = {}",
                sslEvent,
                getClientIp(ctx),
                ChannelUtils.channelInfoForLogging(ctx.channel()),
                sslEvent.cause());
    }

    private void logUnsuccessfulHandshakeWithCause(ChannelHandlerContext ctx, SslHandshakeCompletionEvent sslEvent) {
        logger.debug(
                "Unsuccessful SSL Handshake: {}, client_ip = {}, channel_info = {}, error = {}",
                sslEvent,
                getClientIp(ctx),
                ChannelUtils.channelInfoForLogging(ctx.channel()),
                sslEvent.cause(),
                sslEvent.cause());
    }

    private SslHandshakeInfo buildFailedHandshakeInfo(ChannelHandlerContext ctx) {
        SSLSession session = getSSLSession(ctx);
        if (session == null) {
            return null;
        }

        return SslHandshakeInfo.builder()
                .requestedSni(getRequestedSniFromNames(((ExtendedSSLSession) session).getRequestedServerNames()))
                .isOfIntermediary(isSSlFromIntermediary)
                .build();
    }

    private boolean isTlsHandshakeUsingExternalPsk(ChannelHandlerContext ctx) {
        return Objects.equals(
                ctx.channel()
                        .attr(ZuulPskServer.TLS_HANDSHAKE_USING_EXTERNAL_PSK)
                        .get(),
                true);
    }

    private ClientPSKIdentityInfo getClientPskIdentityInfo(ChannelHandlerContext ctx) {
        return ctx.channel()
                .attr(TlsPskHandler.CLIENT_PSK_IDENTITY_ATTRIBUTE_KEY)
                .get();
    }

    private Certificate getServerCertificate(SSLSession session) {
        if (session.getLocalCertificates() == null || session.getLocalCertificates().length == 0) {
            return null;
        }
        return session.getLocalCertificates()[0];
    }

    private X509Certificate getPeerCertificate(SSLSession session, ClientAuth clientAuth) throws Exception {
        if (clientAuth != ClientAuth.REQUIRE && clientAuth != ClientAuth.OPTIONAL) {
            return null;
        }
        if (session.getPeerCertificates() == null || session.getPeerCertificates().length == 0) {
            return null;
        }
        return (X509Certificate) session.getPeerCertificates()[0];
    }

    private String getRequestedSni(SSLSession session) {
        try {
            return getRequestedSniFromNames(((ExtendedSSLSession) session).getRequestedServerNames());
        } catch (Exception e) {
            logger.warn("Error getting the request server names.", e);
            return "none";
        }
    }

    private String getRequestedSniFromNames(List<SNIServerName> serverNames) {
        if (serverNames == null) {
            return "none";
        }
        return serverNames.stream()
                .filter(sni -> sni instanceof SNIHostName)
                .findFirst()
                .map(sni -> ((SNIHostName) sni).getAsciiName())
                .orElse("none");
    }

    private SSLSession getSSLSession(ChannelHandlerContext ctx) {
        SslHandler sslhandler = ctx.channel().pipeline().get(SslHandler.class);
        if (sslhandler != null) {
            return sslhandler.engine().getSession();
        }
        TlsPskHandler tlsPskHandler = ctx.channel().pipeline().get(TlsPskHandler.class);
        if (tlsPskHandler != null) {
            return tlsPskHandler.getSession();
        }
        return null;
    }

    private ClientAuth whichClientAuthEnum(ChannelHandlerContext ctx) {
        SslHandler sslhandler = ctx.channel().pipeline().get(SslHandler.class);
        if (sslhandler == null) {
            return ClientAuth.NONE;
        }

        ClientAuth clientAuth;
        if (sslhandler.engine().getNeedClientAuth()) {
            clientAuth = ClientAuth.REQUIRE;
        } else if (sslhandler.engine().getWantClientAuth()) {
            clientAuth = ClientAuth.OPTIONAL;
        } else {
            clientAuth = ClientAuth.NONE;
        }
        return clientAuth;
    }

    private void incrementCounters(
            SslHandshakeCompletionEvent sslHandshakeCompletionEvent, SslHandshakeInfo handshakeInfo) {
        try {
            List<Tag> tagList = new ArrayList<>();
            tagList.add(Tag.of("listener", listenerName));
            if (sslHandshakeCompletionEvent.isSuccess()) addSuccessTags(tagList, handshakeInfo);
            if (!sslHandshakeCompletionEvent.isSuccess())
                tagList.add(Tag.of("failure_cause", getFailureCause(sslHandshakeCompletionEvent.cause())));
            tagList.add(Tag.of("success", String.valueOf(sslHandshakeCompletionEvent.isSuccess())));
            if (SNI_LOGGING_ENABLED.get()) tagList.add(Tag.of("sni", handshakeInfo.getRequestedSni()));
            spectatorRegistry.counter("server.ssl.handshake", tagList).increment();
        } catch (Exception e) {
            logger.error("Error incrementing counters for SSL handshake!", e);
        }
    }

    private void addSuccessTags(List<Tag> tagList, SslHandshakeInfo handshakeInfo) {
        tagList.add(Tag.of("protocol", handshakeInfo.getProtocol().isEmpty() ? "unknown" : handshakeInfo.getProtocol()));
        tagList.add(Tag.of(
                "ciphersuite",
                handshakeInfo.getCipherSuite().isEmpty() ? "unknown" : handshakeInfo.getCipherSuite()));
        tagList.add(Tag.of("clientauth", String.valueOf(handshakeInfo.getClientAuthRequirement())));
        tagList.add(Tag.of("namedgroup", Objects.requireNonNullElse(handshakeInfo.getNamedGroup(), "unknown")));
    }

    @VisibleForTesting
    String getFailureCause(Throwable throwable) {
        String message = throwable.getMessage();
        if (message == null) {
            return throwable.toString();
        }

        Matcher matcher = OPEN_SSL_PATTERN.matcher(message);
        return matcher.find() ? matcher.group(1) : message;
    }
}
