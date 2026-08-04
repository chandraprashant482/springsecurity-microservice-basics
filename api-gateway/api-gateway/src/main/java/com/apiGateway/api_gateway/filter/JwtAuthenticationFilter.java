package com.apiGateway.api_gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered
{

    private static final String SECRET_KEY = "fjfhgdhg-hkhoiuioew-hjdchwdkjlh-;sjdlkdwco7j";

    private static final List<String> openApiEndpoints = List.of(
            "/auth/api/v1/auth/register",
            "/auth/api/v1/auth/login"
    );


    private static final Map<String, List<String>> protectedEndpointsWithRoles = Map.of(
     //       "/auth/api/v1/welcome/message", List.of("ROLE_ADMIN"),
            "/micro1/message", List.of("ROLE_ADMIN")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestPath = exchange.getRequest().getURI().getPath();
        if (isPublicEndpoint(requestPath)){
            return chain.filter(exchange);
        }
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        String token = authHeader.substring(7);
        try {
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(SECRET_KEY))
                    .build()
                    .verify(token);
            String role = jwt.getClaim("role").asString();
            System.out.println("Requested Path : "+requestPath);
            System.out.println("role "+role);
            if (!isAuthorized(requestPath,role)){
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
            exchange=exchange.mutate().request(r->r.header("X-User-Role",role))
                    .build();
        }catch (JWTVerificationException e){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }

    private boolean isPublicEndpoint(String path){
        return  openApiEndpoints.stream().anyMatch(path::equalsIgnoreCase);
    }

    private boolean isAuthorized(String path, String role) {
        for (Map.Entry<String, List<String>> entry : protectedEndpointsWithRoles.entrySet()) {
            String protectedPath = entry.getKey();
            List<String> allowedRoles = entry.getValue();

            if (path.startsWith(protectedPath)) {
                System.out.println("Matched protected path: " + protectedPath + " | Allowed roles: " + allowedRoles);
                return allowedRoles.contains(role);
            }
        }
        return true; // Allow access if path is not protected (can be changed to false to deny by default)
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
