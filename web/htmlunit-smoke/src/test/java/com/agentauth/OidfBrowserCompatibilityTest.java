package com.agentauth;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.htmlunit.BrowserVersion;
import org.htmlunit.WebClient;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

class OidfBrowserCompatibilityTest {
    @Test
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

            wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("agent-auth-login-email")
                )
            ).sendKeys("oidf-user@example.com");
            driver.findElement(By.id("agent-auth-login-password"))
                .sendKeys("Replaceable password 123!");
            driver.findElement(By.id("agent-auth-login-submit")).click();

            wait.until(ExpectedConditions.urlContains("/consent?"));
            wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("agent-auth-consent-ready")
                )
            );
            driver.findElement(By.id("agent-auth-consent-approve")).click();

            wait.until(
                ExpectedConditions.presenceOfElementLocated(
                    By.id("submission_complete")
                )
            );
            assertTrue(driver.getCurrentUrl().contains("/callback?code=htmlunit-code"));
        } finally {
            driver.quit();
        }
    }
}
