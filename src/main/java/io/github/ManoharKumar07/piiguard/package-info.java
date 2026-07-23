/**
 * Spring API PII Guard — root package.
 *
 * <p>This library detects PII (Personally Identifiable Information) and sensitive
 * data exposure in Spring Boot REST APIs by scanning controllers, endpoints, and
 * their associated DTOs at test-time using Java Reflection and ClassGraph.
 *
 * <h2>Quick Start</h2>
 * <pre>{@code
 * @ExtendWith(PiiGuardExtension.class)
 * class PiiGuardScanTest {
 *     @Test
 *     void scanCompletes() {
 *         // scan runs automatically in beforeAll
 *     }
 * }
 * }</pre>
 *
 * @see io.github.ManoharKumar07.piiguard.extension.PiiGuardExtension
 * @see io.github.ManoharKumar07.piiguard.config.PiiGuardConfiguration
 */
package io.github.ManoharKumar07.piiguard;
