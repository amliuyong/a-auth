package com.agentauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.htmlunit.BrowserVersion;
import org.htmlunit.WebClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

class OidfBrowserCompatibilityTest {
    private static class FixtureDriver extends HtmlUnitDriver {
        FixtureDriver() {
            super(BrowserVersion.CHROME, true);
        }

        @Override
        protected WebClient modifyWebClient(WebClient client) {
            client.getOptions().setThrowExceptionOnScriptError(false);
            client.getOptions().setCssEnabled(false);
            return client;
        }

        void finishBackgroundWork() {
            getWebClient().waitForBackgroundJavaScript(1000);
        }
    }

    private static String fixture(String baseUrl, String method, String path) {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(5))
                .method(method, HttpRequest.BodyPublishers.noBody())
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            return response.body();
        } catch (Exception error) {
            throw new AssertionError("Fixture control request failed", error);
        }
    }

    private static String stage(String value) {
        System.out.println("OIDF HtmlUnit stage: " + value);
        return value;
    }

    @Test
    @Timeout(
        value = 90,
        unit = TimeUnit.SECONDS,
        threadMode = Timeout.ThreadMode.SEPARATE_THREAD
    )
    void productionBundleCompletesLoginConsentAndCallback() {
        completeLogin(null, false);
    }

    @ParameterizedTest
    @CsvSource({
        "default, false", "custom, false", "unavailable, false",
        "default, true", "custom, true", "unavailable, true"
    })
    @Timeout(value = 90, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void brandingPreservesCredentialsBeingEdited(String brandingMode, boolean editingPassword) {
        completeLogin(brandingMode, editingPassword);
    }

    private void completeLogin(String brandingMode, boolean editingPassword) {
        String baseUrl = System.getProperty("oidf.base-url");
        assertTrue(baseUrl != null && baseUrl.startsWith("http://"));

        if (brandingMode != null) fixture(baseUrl, "POST", "/fixture/branding/hold?mode=" + brandingMode);
        FixtureDriver driver = new FixtureDriver();
        String stage = stage("load login page");
        try {
            driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(30));
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(30));
            driver.get(
                baseUrl
                    + "/login?response_type=code&client_id=oidf-client"
                    + "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"
                    + "&scope=openid&code_challenge=challenge"
                    + "&code_challenge_method=S256"
            );

            stage = stage("wait for login readiness");
            wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("agent-auth-login-ready")
                )
            );
            stage = stage("enter password credentials");
            WebElement email = wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("agent-auth-login-email")
                )
            );
            WebElement password = driver.findElement(
                By.id("agent-auth-login-password")
            );
            email.clear();
            password.clear();
            if (brandingMode != null) {
                wait.until(ignored -> fixture(baseUrl, "GET", "/fixture/branding/pending").equals("pending"));
                WebElement edited = editingPassword ? password : email;
                String prefix = editingPassword ? "Replaceable " : "oidf-";
                if (editingPassword) email.sendKeys("oidf-user@example.com");
                edited.sendKeys(prefix);
                stage = stage("resolve branding during credential editing");
                fixture(baseUrl, "POST", "/fixture/branding/release");
                if (brandingMode.equals("custom")) {
                    wait.until(ExpectedConditions.textToBePresentInElementLocated(
                        By.cssSelector("header"), "Delayed Brand"
                    ));
                }
                driver.finishBackgroundWork();
                assertEquals(prefix, driver.executeScript("return arguments[0].value", edited),
                    "Credential prefix must survive branding");
                if (editingPassword) password.sendKeys("password 123!");
                else {
                    email.sendKeys("user@example.com");
                    password.sendKeys("Replaceable password 123!");
                }
            } else {
                email.sendKeys("oidf-user@example.com");
                password.sendKeys("Replaceable password 123!");
            }
            assertEquals("oidf-user@example.com", driver.executeScript("return arguments[0].value", email));
            assertEquals("Replaceable password 123!", driver.executeScript("return arguments[0].value", password));
            stage = stage("submit password login");
            driver.findElement(By.id("agent-auth-login-submit")).click();

            wait.until(ExpectedConditions.urlContains("/consent?"));
            stage = stage("wait for consent readiness");
            wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("agent-auth-consent-ready")
                )
            );
            stage = stage("approve consent");
            driver.findElement(By.id("agent-auth-consent-approve")).click();

            wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("submission_complete")
                )
            );
            assertTrue(driver.getCurrentUrl().contains("/callback?code=htmlunit-code"));
        } catch (RuntimeException | AssertionError error) {
            throw new AssertionError(
                "OIDF HtmlUnit smoke failed during "
                    + stage
                    + " at "
                    + driver.getCurrentUrl(),
                error
            );
        } finally {
            driver.quit();
            if (brandingMode != null) fixture(baseUrl, "POST", "/fixture/branding/release");
        }
    }
}
