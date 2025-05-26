/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.gateway.ha.security;

import io.airlift.log.Logger;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;

import static jakarta.ws.rs.core.NewCookie.SameSite.NONE;

public final class SessionCookie
{
    private static final Logger log = Logger.get(SessionCookie.class);

    static final String OAUTH_ID_TOKEN = "token";
    static final String SELF_ISSUER_ID = "self";
    static final int MAX_COOKIE_CHUNK_SIZE = 3800;
    static final int MAX_CHUNKS_TO_CLEAN = 10;

    private SessionCookie() {}

    public static List<NewCookie> getTokenCookies(String token)
    {
        List<NewCookie> cookies = new ArrayList<>();
        int tokenLength = token.length();
        int chunkCount = (int) Math.ceil((double) tokenLength / MAX_COOKIE_CHUNK_SIZE);

        // Set current token chunk cookies
        for (int i = 0; i < chunkCount; i++) {
            int start = i * MAX_COOKIE_CHUNK_SIZE;
            int end = Math.min(start + MAX_COOKIE_CHUNK_SIZE, tokenLength);
            String chunk = token.substring(start, end);
            String cookieName = OAUTH_ID_TOKEN + "_" + i;

            log.error("Creating token chunk cookie — length = %d, begins with = %s",
                    chunk.length(),
                    chunk.substring(0, Math.min(chunk.length(), 20)));

            NewCookie cookie = new NewCookie.Builder(cookieName)
                    .value(chunk)
                    .path("/")
                    .domain("")
                    .comment("Chunk " + (i + 1) + " of " + chunkCount)
                    .maxAge(60 * 60 * 24)
                    .secure(true)
                    .httpOnly(false)
                    .sameSite(NONE)
                    .build();

            cookies.add(cookie);
        }

        // Delete any extra cookies beyond chunkCount
        for (int i = chunkCount; i < MAX_CHUNKS_TO_CLEAN; i++) {
            String cookieName = COOKIE_NAME_BASE + "_" + i;
            NewCookie deleteCookie = new NewCookie.Builder(cookieName)
                    .value("")
                    .path("/")
                    .domain("")
                    .maxAge(0)
                    .secure(true)
                    .httpOnly(false)
                    .sameSite(NewCookie.SameSite.NONE)
                    .build();

            cookies.add(deleteCookie);
        }

        return cookies;
    }

    public static String getTokenFromCookies(ContainerRequestContext requestContext)
    {
        Map<String, Cookie> cookies = requestContext.getCookies();
        final String prefix = OAUTH_ID_TOKEN + "_";

        List<Map.Entry<Integer, String>> chunks = cookies.entrySet().stream()
                .filter(e -> e.getKey().startsWith(prefix))
                .map(e ->
                {
                    try {
                        int index = Integer.parseInt(e.getKey().substring(prefix.length()));
                        return Map.entry(index, e.getValue().getValue());
                    } catch (NumberFormatException ex) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .sorted(Comparator.comparingInt(Map.Entry::getKey))
                .collect(Collectors.toList());

        if (chunks.isEmpty()) {
            return null;
        }

        return chunks.stream()
                .map(Map.Entry::getValue)
                .collect(Collectors.joining());
    }

    public static Response logOut()
    {
        NewCookie cookie = new NewCookie.Builder(OAUTH_ID_TOKEN)
                .value("logout")
                .path("/")
                .domain("")
                .comment("")
                .maxAge(0)
                .secure(true)
                .build();
        return Response.ok("You are logged out successfully.")
                .cookie(cookie)
                .build();
    }
}
