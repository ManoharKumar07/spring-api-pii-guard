package io.github.manoharkumar07.piiguard.scan;

import io.github.manoharkumar07.piiguard.fixtures.controllers.SafeProductController;
import io.github.manoharkumar07.piiguard.fixtures.controllers.VulnerableUserController;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EndpointAnalyzerTest {

    private EndpointAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new EndpointAnalyzer(new DtoFieldExtractor(), 5);
    }

    @Test
    void extractsGetEndpointWithPathVariable() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(VulnerableUserController.class);

        ScannedEndpoint getUser = findEndpoint(endpoints, "GET", "/api/users/{id}");

        assertThat(getUser).isNotNull();
        assertThat(getUser.path()).isEqualTo("/api/users/{id}");
        assertThat(getUser.pathVariables()).hasSize(1);
        assertThat(getUser.pathVariables().get(0).name()).isEqualTo("id");
    }

    @Test
    void extractsGetAllEndpoint() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(VulnerableUserController.class);

        ScannedEndpoint getAll = findEndpoint(endpoints, "GET", "/api/users");

        assertThat(getAll).isNotNull();
        assertThat(getAll.responseDto()).isNotNull();
        assertThat(getAll.responseDto().className()).contains("UserWithSsnDto");
    }

    @Test
    void extractsPostEndpointWithRequestBody() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(VulnerableUserController.class);

        ScannedEndpoint create = findEndpoint(endpoints, "POST", "/api/users");

        assertThat(create).isNotNull();
        assertThat(create.requestDto()).isNotNull();
        assertThat(create.requestDto().className()).contains("CreateUserRequest");
    }

    @Test
    void unwrapsResponseEntityGeneric() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(VulnerableUserController.class);

        ScannedEndpoint create = findEndpoint(endpoints, "POST", "/api/users");

        assertThat(create.responseDto()).isNotNull();
        assertThat(create.responseDto().className()).contains("UserTokenDto");
    }

    @Test
    void unwrapsListReturnType() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(SafeProductController.class);

        // ResponseEntity<List<ProductDto>> should unwrap to ProductDto
        ScannedEndpoint listProducts = findEndpoint(endpoints, "GET", "/api/products");

        assertThat(listProducts).isNotNull();
        assertThat(listProducts.responseDto()).isNotNull();
        assertThat(listProducts.responseDto().className()).contains("ProductDto");
    }

    @Test
    void handlesVoidReturnType() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(VulnerableUserController.class);

        ScannedEndpoint delete = findEndpoint(endpoints, "DELETE", "/api/users/{id}");

        assertThat(delete).isNotNull();
        assertThat(delete.responseDto()).isNull();
    }

    @Test
    void extractsQueryParameter() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(SafeProductController.class);

        ScannedEndpoint listProducts = findEndpoint(endpoints, "GET", "/api/products");

        assertThat(listProducts).isNotNull();
        assertThat(listProducts.queryParameters()).hasSize(1);
        assertThat(listProducts.queryParameters().get(0).name()).isEqualTo("page");
    }

    @Test
    void setsControllerClassName() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(SafeProductController.class);

        assertThat(endpoints).allMatch(e -> e.controllerClass()
                .equals(SafeProductController.class.getName()));
    }

    @Test
    void prefixesPathWithClassLevelMapping() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(SafeProductController.class);

        assertThat(endpoints).allMatch(e -> e.path().startsWith("/api/products"));
    }

    @Test
    void discoversAllFiveMappedMethods() {
        List<ScannedEndpoint> endpoints = analyzer.analyze(VulnerableUserController.class);

        // GET /{id}, GET /, POST /, PUT /{id}, DELETE /{id}
        assertThat(endpoints).hasSize(5);
        assertThat(endpoints).extracting(ScannedEndpoint::httpMethod)
                .containsExactlyInAnyOrder("GET", "GET", "POST", "PUT", "DELETE");
    }

    // -----------------------------------------------------------------------

    private ScannedEndpoint findEndpoint(List<ScannedEndpoint> endpoints, String method, String path) {
        return endpoints.stream()
                .filter(e -> e.httpMethod().equals(method) && e.path().equals(path))
                .findFirst()
                .orElse(null);
    }
}
