/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.samples.sandbox.net;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Network client entitled to make outbound connections.
 *
 * <p>This class is in the {@code org.jguard.samples.sandbox.net} package,
 * which is entitled to {@code network.outbound} capability.
 */
public final class NetworkClient {

    private final HttpClient client;

    public NetworkClient() {
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    /**
     * Fetches the HTTP status code from a URL.
     *
     * @param url the URL to fetch
     * @return the HTTP status code
     * @throws IOException if the request fails
     * @throws InterruptedException if the request is interrupted
     */
    public int fetchStatus(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .GET()
            .timeout(Duration.ofSeconds(10))
            .build();

        HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
        return response.statusCode();
    }
}
