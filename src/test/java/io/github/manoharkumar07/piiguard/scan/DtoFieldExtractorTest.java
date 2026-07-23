package io.github.manoharkumar07.piiguard.scan;

import io.github.manoharkumar07.piiguard.fixtures.dto.*;
import io.github.manoharkumar07.piiguard.model.DtoInfo;
import io.github.manoharkumar07.piiguard.model.FieldInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class DtoFieldExtractorTest {

    private DtoFieldExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new DtoFieldExtractor();
    }

    @Test
    void extractsSimpleFields() {
        DtoInfo info = extractor.extract(ProductDto.class, 5);

        assertThat(info.className()).isEqualTo(ProductDto.class.getName());
        assertThat(info.fields()).hasSize(5);
        assertThat(info.fields()).extracting(FieldInfo::name)
                .containsExactlyInAnyOrder("id", "name", "description", "price", "category");
    }

    @Test
    void extractsInheritedFields() {
        DtoInfo info = extractor.extract(InheritedFieldsDto.class, 5);

        // Own fields (InheritedFieldsDto): username, email
        // Inherited fields (BaseDto): id, createdAt
        assertThat(info.fields()).extracting(FieldInfo::name)
                .contains("id", "createdAt", "username", "email");
    }

    @Test
    void handlesCircularReferences() {
        // Must not throw StackOverflowError
        DtoInfo info = extractor.extract(CircularADto.class, 5);

        assertThat(info).isNotNull();
        assertThat(info.fields()).extracting(FieldInfo::name).contains("id", "name", "related");

        FieldInfo relatedField = info.fields().stream()
                .filter(f -> f.name().equals("related"))
                .findFirst()
                .orElseThrow();

        // CircularBDto is extracted
        assertThat(relatedField.nestedDto()).isNotNull();
        assertThat(relatedField.nestedDto().className()).contains("CircularBDto");

        // The back-reference 'owner' in CircularBDto should stop recursion (visited set)
        Optional<FieldInfo> ownerField = relatedField.nestedDto().fields().stream()
                .filter(f -> f.name().equals("owner"))
                .findFirst();
        assertThat(ownerField).isPresent();
        // owner.nestedDto is a terminal DtoInfo with empty fields — cycle was detected
        assertThat(ownerField.get().nestedDto()).isNotNull();
        assertThat(ownerField.get().nestedDto().fields()).isEmpty();
    }

    @Test
    void respectsMaxDepthLimit() {
        // With depth=1, root fields are extracted but their children are terminal
        DtoInfo info = extractor.extract(DeepNestedDto.class, 1);

        assertThat(info.fields()).extracting(FieldInfo::name).contains("value", "child");

        FieldInfo childField = info.fields().stream()
                .filter(f -> f.name().equals("child"))
                .findFirst()
                .orElseThrow();

        // At depth 1, the child's own fields are not explored (remainingDepth reaches 0)
        assertThat(childField.nestedDto()).isNotNull();
        assertThat(childField.nestedDto().fields()).isEmpty();
    }

    @Test
    void returnsTerminalDtoForStringType() {
        DtoInfo info = extractor.extract(String.class, 5);

        assertThat(info.fields()).isEmpty();
    }

    @Test
    void returnsTerminalDtoForPrimitiveWrapper() {
        DtoInfo info = extractor.extract(Long.class, 5);

        assertThat(info.fields()).isEmpty();
    }

    @Test
    void setsJsonNameToFieldNameWhenNoAnnotation() {
        DtoInfo info = extractor.extract(ProductDto.class, 5);

        // ProductDto has no @JsonProperty annotations — jsonName should equal name
        assertThat(info.fields()).allMatch(f -> f.jsonName().equals(f.name()));
    }

    @Test
    void identifiesNonCollectionFields() {
        DtoInfo info = extractor.extract(UserWithPasswordDto.class, 5);

        assertThat(info.fields()).noneMatch(FieldInfo::isCollection);
    }

    @Test
    void extractsCredentialFieldNames() {
        DtoInfo info = extractor.extract(UserWithPasswordDto.class, 5);

        assertThat(info.fields()).extracting(FieldInfo::name)
                .contains("password", "passwordHash");
    }

    @Test
    void extractsGovernmentIdFieldNames() {
        DtoInfo info = extractor.extract(UserWithSsnDto.class, 5);

        assertThat(info.fields()).extracting(FieldInfo::name)
                .contains("socialSecurityNumber", "aadhaarNumber");
    }
}
