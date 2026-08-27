package com.agentauth;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.htmlunit.BrowserVersion;
import org.htmlunit.WebClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

class OidfBrowserCompatibilityTest {
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
        String baseUrl = System.getProperty("oidf.base-url");
        assertTrue(baseUrl != null && baseUrl.startsWith("http://"));

        HtmlUnitDriver driver = new HtmlUnitDriver(BrowserVersion.CHROME, true) {
            @Override
            protected WebClient modifyWebClient(WebClient client) {
                client.getOptions().setThrowExceptionOnScriptError(false);
                client.getOptions().setCssEnabled(false);
                return client;
            }
        };
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
            email.sendKeys("oidf-user@example.com");
            password.clear();
            password.sendKeys("Replaceable password 123!");
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
        }
    }
}
