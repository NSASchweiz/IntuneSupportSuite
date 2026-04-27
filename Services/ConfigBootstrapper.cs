using System.Text.RegularExpressions;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class ConfigBootstrapper
{
    private const string CurrentConfigVersion = "1.1.1-Test-hotfix6";
    private readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    private readonly TrustedConfigValidator _validator = new();
    private readonly ConfigPathValidator _pathValidator = new();
    private readonly ConfigTimeIntervalValidator _timeIntervalValidator = new();
    private readonly ConfigLogManagementValidator _logManagementValidator = new();
    private readonly object _runtimeTrustCacheSync = new();
    private RuntimeTrustCacheEntry? _runtimeTrustCache;


    private void InvalidateRuntimeTrustCache()
    {
        lock (_runtimeTrustCacheSync)
        {
            _runtimeTrustCache = null;
        }
    }

    private string BuildRuntimeTrustCacheKey(AppConfig config)
    {
        static string DescribeFile(string? path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return "missing";
            }

            var info = new FileInfo(path);
            return $"{info.FullName}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
        }

        var executableDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var catalogPath = Path.Combine(executableDirectory, "catalog", "TrustedConfig.cat");
        var exePath = Environment.ProcessPath ?? Path.Combine(executableDirectory, "DapIntuneSupportSuite.exe");
        return string.Join("||",
            DescribeFile(config.TrustedConfigFilePath),
            DescribeFile(catalogPath),
            DescribeFile(exePath));
    }

    private bool TryGetRuntimeTrustCache(string cacheKey, AppConfig targetConfig, out RuntimeTrustCheckResult result)
    {
        lock (_runtimeTrustCacheSync)
        {
            if (_runtimeTrustCache is null || !string.Equals(_runtimeTrustCache.CacheKey, cacheKey, StringComparison.Ordinal))
            {
                result = new RuntimeTrustCheckResult();
                return false;
            }

            if (!_runtimeTrustCache.Result.Allowed || _runtimeTrustCache.CachedConfig.TrustState != TrustState.Trusted)
            {
                _runtimeTrustCache = null;
                result = new RuntimeTrustCheckResult();
                return false;
            }

            targetConfig.CopyFrom(_runtimeTrustCache.CachedConfig.Clone());
            targetConfig.TrustState = TrustState.Trusted;
            targetConfig.IsSimulationModeEnforced = false;
            result = new RuntimeTrustCheckResult
            {
                Allowed = true,
                Message = string.IsNullOrWhiteSpace(_runtimeTrustCache.Result.Message)
                    ? (string.IsNullOrWhiteSpace(targetConfig.ValidationSummary) ? "Trusted" : targetConfig.ValidationSummary)
                    : _runtimeTrustCache.Result.Message,
                SessionShouldClose = false,
                SourceHost = Environment.MachineName,
                DestinationHost = string.Empty
            };
            return true;
        }
    }

    private void StoreRuntimeTrustCache(string cacheKey, AppConfig config, RuntimeTrustCheckResult result)
    {
        lock (_runtimeTrustCacheSync)
        {
            _runtimeTrustCache = new RuntimeTrustCacheEntry
            {
                CacheKey = cacheKey,
                CachedConfig = config.Clone(),
                Result = result
            };
        }
    }

    public ConfigurationBootstrapResult EnsureAndLoad()
    {
        var executableDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var trustLogPath = Path.Combine(executableDirectory, "AppLog", "Trust.log");
        var trustLogger = new TrustLogger(trustLogPath);
        const string operationId = "BOOT";

        trustLogger.Info("TrustedConfigStartupCheck", "Started", "Startprüfung TrustedConfig gestartet.", operationId);

        var sourceUserConfigPath = Path.Combine(executableDirectory, "Config", "config.json");
        EnsureProgramUserConfigExists(sourceUserConfigPath);

        var sourceUserConfig = DeserializeUserConfig(sourceUserConfigPath);
        LanguageManager.Instance.Load(executableDirectory, sourceUserConfig.Language, null);

        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userConfigPath = EnsureUserConfigForLanguage(roamingAppData, sourceUserConfigPath, sourceUserConfig);
        var userConfig = DeserializeUserConfig(userConfigPath);

        var trustedDirectory = Path.Combine(executableDirectory, "TrustedConfig");
        var trustedConfigPath = Path.Combine(trustedDirectory, "TrustedConfig.json");
        var catalogDirectory = Path.Combine(executableDirectory, "catalog");
        var trustedCatalogPath = Path.Combine(catalogDirectory, "TrustedConfig.cat");

        trustLogger.Info("TrustedConfigPathCheck", "Started", $"Pfadprüfung für {trustedConfigPath}", operationId);
        if (!Directory.Exists(trustedDirectory) || !File.Exists(trustedConfigPath))
        {
            var message = "TrustedConfig.json fehlt. Bitte stellen Sie ProgramDir\\TrustedConfig\\TrustedConfig.json bereit.";
            trustLogger.Error("TrustedConfigFileCheck", "Failed", message, operationId);
            return CreateFatalResult(userConfig, userConfigPath, trustedConfigPath, trustLogPath, message);
        }

        trustLogger.Info("TrustedConfigCatalogPathCheck", "Started", $"Pfadprüfung für {trustedCatalogPath}", operationId);
        if (!Directory.Exists(catalogDirectory) || !File.Exists(trustedCatalogPath))
        {
            var message = "TrustedConfig.cat fehlt. Bitte stellen Sie ProgramDir\\catalog\\TrustedConfig.cat bereit.";
            trustLogger.Error("TrustedConfigCatalogFileCheck", "Failed", message, operationId);
            return CreateFatalResult(userConfig, userConfigPath, trustedConfigPath, trustLogPath, message);
        }

        var aclValid = CheckTrustedDirectoryAcl(trustedDirectory);
        trustLogger.Info("TrustedConfigAclCheck", aclValid ? "Success" : "Failed", aclValid ? "ACL-Prüfung erfolgreich." : "ACL-Prüfung fehlgeschlagen.", operationId);

        var validationContext = _validator.LoadAndValidateFromDisk(trustedConfigPath, userConfig, trustedConfigPath, trustLogPath);
        LogValidationEvents(trustLogger, validationContext.Validation, operationId);
        LogAllowListEvents(trustLogger, validationContext.RuntimeConfig.AllowedSources, validationContext.RuntimeConfig.AllowedDestinations, validationContext.Validation, operationId);

        var verifier = new AuthentiCodeVerifier();
        var catalogVerifier = new FileCatalogVerifier();
        var exePath = Environment.ProcessPath ?? Path.Combine(executableDirectory, "DapIntuneSupportSuite.exe");
        var exeSignature = verifier.Verify(exePath);
        var trustedCatalogSignature = verifier.Verify(trustedCatalogPath);
        var catalogMatch = catalogVerifier.Verify(trustedCatalogPath, trustedConfigPath);
        var sameSigner = trustedCatalogSignature.Success && exeSignature.Success &&
                         !string.IsNullOrWhiteSpace(trustedCatalogSignature.Thumbprint) &&
                         !string.IsNullOrWhiteSpace(exeSignature.Thumbprint) &&
                         string.Equals(trustedCatalogSignature.Thumbprint, exeSignature.Thumbprint, StringComparison.OrdinalIgnoreCase) &&
                         string.Equals(trustedCatalogSignature.PublicKey, exeSignature.PublicKey, StringComparison.Ordinal);

        trustLogger.Info("TrustedConfigCatalogSignatureCheck", trustedCatalogSignature.Success ? "Success" : "Failed", $"Signaturstatus={trustedCatalogSignature.Status}; Thumbprint={trustedCatalogSignature.Thumbprint}; Message={trustedCatalogSignature.StatusMessage}", operationId);
        trustLogger.Info("TrustedConfigCatalogMatchCheck", catalogMatch.Success ? "Success" : "Failed", $"CatalogStatus={catalogMatch.Status}; SignatureStatus={catalogMatch.SignatureStatus}; Message={catalogMatch.StatusMessage}", operationId);
        trustLogger.Info("TrustedConfigSignerMatch", sameSigner ? "Success" : "Failed", sameSigner ? "Signer des Catalogs identisch mit EXE." : "Signer des Catalogs nicht identisch mit EXE.", operationId);

        var trustState = DetermineTrustState(trustedCatalogSignature, catalogMatch, sameSigner, validationContext.Validation, aclValid);
        if (trustState == TrustState.Broken && HasAllowListErrors(validationContext.Validation))
        {
            trustLogger.Error("AllowListTrustState", "Broken", "Wechsel des Trust States aufgrund fehlerhafter Allow-Liste.", operationId);
        }
        var runtimeConfig = BuildRuntimeConfig(userConfig, validationContext.RuntimeConfig, userConfigPath, trustedConfigPath, trustState, trustedCatalogSignature, catalogMatch, string.Empty);
        var runtimeTrustCacheKey = BuildRuntimeTrustCacheKey(runtimeConfig);
        ApplyValidationMetadata(runtimeConfig, validationContext.Validation);
        runtimeConfig.StartupSecurityBlockReason = string.Empty;

        var pathValidation = _pathValidator.ValidateForStartup(userConfig, runtimeConfig);
        LogPathValidationEvents(trustLogger, pathValidation, operationId, isStartup: true);
        if (pathValidation.HasCriticalIssues)
        {
            var message = $"Kritischer Pfadfehler in der Konfiguration erkannt. {pathValidation.Summary}";
            trustLogger.Error("PathValidationStartup", "Blocked", "App-Start wegen kritischem Pfadfehler abgebrochen.", operationId);
            return CreateFatalResult(userConfig, userConfigPath, trustedConfigPath, trustLogPath, message);
        }

        string startupMessage = string.Empty;
        var showWarningPopup = false;
        if (pathValidation.HasInformationalIssues)
        {
            startupMessage = $"Hinweis zur Pfadvalidierung: {pathValidation.Summary}";
            showWarningPopup = true;
        }

        if (trustState == TrustState.Trusted)
        {
            trustLogger.Info("StartupSourceHostCheck", "Started", $"App-Startprüfung des Quellhosts '{Environment.MachineName}' gestartet.", operationId, Environment.MachineName, null, "Startup");
            var startupSourceCheck = EnforceAllowedSource(runtimeConfig, "Startup", Environment.MachineName, string.Empty, operationId, trustLogger);
            if (!startupSourceCheck.Allowed)
            {
                runtimeConfig.IsSimulationModeEnforced = true;
                runtimeConfig.SimulationMode = true;
                runtimeConfig.StartupSecurityBlockReason = "Quellhost nicht erlaubt – produktiver Modus gesperrt. Simulationsmodus erzwungen.";
                startupMessage = $"{startupSourceCheck.Message} Simulationsmodus wird bereits beim Start erzwungen.";
                showWarningPopup = true;
                trustLogger.Warn("StartupSourceHostCheck", "Blocked", startupMessage, operationId, Environment.MachineName, null, "Startup", startupSourceCheck.SourceIps, startupSourceCheck.DestinationIps, startupSourceCheck.MatchedAllowEntry);
                trustLogger.Warn("StartupSimulationModeEnforced", "Blocked", "Simulationsmodus wegen Quellhost-Mismatch erzwungen.", operationId, Environment.MachineName, null, "Startup", startupSourceCheck.SourceIps, startupSourceCheck.DestinationIps, startupSourceCheck.MatchedAllowEntry);
            }
        }

        if (trustState != TrustState.Trusted)
        {
            BackupUntrustedTrustedConfig(trustedConfigPath, trustLogger, operationId);
            showWarningPopup = true;
            if (trustState == TrustState.Broken)
            {
                startupMessage = $"TrustedConfig ist strukturell oder logisch fehlerhaft. {validationContext.Validation.ValidationSummary} Die App erzwingt den Simulationsmodus.";
                trustLogger.Error("TrustedConfigState", trustState.ToString(), startupMessage, operationId);
                trustLogger.Error("TrustStateTransition", "Broken", "Wechsel in Broken aufgrund von Validierungsfehlern.", operationId);
            }
            else if (!aclValid)
            {
                startupMessage = "TrustedConfig oder TrustedConfig-Verzeichnis erfüllen die erwarteten ACL-Anforderungen nicht. Die App erzwingt den Simulationsmodus.";
                trustLogger.Warn("TrustedConfigState", trustState.ToString(), startupMessage, operationId);
            }
            else if (!catalogMatch.Success)
            {
                startupMessage = $"TrustedConfig-Catalog-Prüfung fehlgeschlagen: {catalogMatch.StatusMessage} Die App erzwingt den Simulationsmodus.";
                trustLogger.Warn("TrustedConfigState", trustState.ToString(), startupMessage, operationId);
            }
            else
            {
                startupMessage = "TrustedConfig.cat ist nicht gültig signiert oder der Signer stimmt nicht mit der EXE überein. Die App erzwingt den Simulationsmodus.";
                trustLogger.Warn("TrustedConfigState", trustState.ToString(), startupMessage, operationId);
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(startupMessage))
            {
                startupMessage = validationContext.Validation.HasWarnings
                    ? $"TrustedConfig ist vertrauenswürdig, enthält aber Warnungen. {validationContext.Validation.ValidationSummary}"
                    : "TrustedConfig wurde erfolgreich als vertrauenswürdig erkannt.";
            }

            trustLogger.Info("TrustedConfigState", trustState.ToString(), startupMessage, operationId);
            trustLogger.Info("TrustedConfigConsistentState", "Trusted", "Wiedererkennung eines konsistenten Trusted-Zustands.", operationId);
        }

        if (pathValidation.HasInformationalIssues && !string.IsNullOrWhiteSpace(pathValidation.Summary) && !startupMessage.Contains(pathValidation.Summary, StringComparison.Ordinal))
        {
            startupMessage = string.IsNullOrWhiteSpace(startupMessage)
                ? $"Hinweis zur Pfadvalidierung: {pathValidation.Summary}"
                : startupMessage + Environment.NewLine + Environment.NewLine + "Hinweis zur Pfadvalidierung: " + pathValidation.Summary;
            showWarningPopup = true;
        }

        runtimeConfig.ConfigVersion = CurrentConfigVersion;
        runtimeConfig.LastSignatureValidation = trustState == TrustState.Trusted
            ? "TrustedConfig.cat ist gültig signiert, passt zu TrustedConfig.json und der Signer stimmt mit der EXE überein."
            : string.IsNullOrWhiteSpace(startupMessage)
                ? (string.IsNullOrWhiteSpace(catalogMatch.StatusMessage) ? trustedCatalogSignature.StatusMessage : catalogMatch.StatusMessage)
                : startupMessage;
        runtimeConfig.LastTrustedSignerThumbprint = trustedCatalogSignature.Thumbprint;
        runtimeConfig.IsSimulationModeEnforced = trustState != TrustState.Trusted;
        runtimeConfig.TrustState = trustState;
        if (runtimeConfig.IsSimulationModeEnforced)
        {
            runtimeConfig.SimulationMode = true;
        }

        if (runtimeConfig.TrustState == TrustState.Trusted)
        {
            StoreRuntimeTrustCache(runtimeTrustCacheKey, runtimeConfig, new RuntimeTrustCheckResult
            {
                Allowed = true,
                Message = string.IsNullOrWhiteSpace(runtimeConfig.StartupSecurityBlockReason) ? startupMessage : runtimeConfig.StartupSecurityBlockReason,
                SessionShouldClose = false,
                SourceHost = Environment.MachineName,
                DestinationHost = string.Empty
            });
        }
        else
        {
            InvalidateRuntimeTrustCache();
        }

        return new ConfigurationBootstrapResult
        {
            Config = runtimeConfig,
            UserConfig = userConfig,
            TrustedConfig = validationContext.TrustedConfig,
            UserConfigPath = userConfigPath,
            TrustedConfigPath = trustedConfigPath,
            TrustState = trustState,
            StartupMessage = startupMessage,
            ExitApplication = false,
            ShowWarningPopup = showWarningPopup,
            ShowTrustedInfoPopup = false
        };
    }

    public ConfigSaveResult SaveUserConfiguration(AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.ConfigFilePath))
        {
            throw new InvalidOperationException("ConfigFilePath ist nicht gesetzt.");
        }

        LanguageManager.Instance.Load(AppContext.BaseDirectory, config.Language, null);
        LanguageManager.Instance.ApplyLanguageDrivenConfigFields(config);

        var trustLogger = new TrustLogger(config.TrustLogPath, config);
        const string operationId = "USERCONFIG-SAVE";

        var pathValidation = FilterUserPathValidation(_pathValidator.ValidateForSave(config));
        LogPathValidationEvents(trustLogger, pathValidation, operationId, isStartup: false);

        var timeIntervalValidation = _timeIntervalValidator.ValidateForSave(config);
        var logManagementValidation = _logManagementValidator.ValidateForSave(config);
        LogTimeIntervalValidationEvents(trustLogger, timeIntervalValidation, operationId);
        LogLogManagementValidationEvents(trustLogger, logManagementValidation, operationId);

        if (pathValidation.HasCriticalIssues)
        {
            trustLogger.Error("UserConfigPathValidationSave", "Blocked", "Speichern wegen kritischem Pfadfehler blockiert.", operationId);
            throw new InvalidOperationException($"Konfiguration enthält kritische Pfadfehler. Speichern wurde blockiert. {pathValidation.Summary}");
        }

        if (timeIntervalValidation.HasCriticalIssues)
        {
            trustLogger.Error("UserConfigTimeIntervalValidationSave", "Blocked", "Speichern wegen kritischem Zeit-/Intervallwert blockiert.", operationId);
            throw new InvalidOperationException($"Konfiguration enthält kritische Zeit- oder Intervallwerte. Speichern wurde blockiert. {timeIntervalValidation.Summary}");
        }

        if (logManagementValidation.HasCriticalIssues)
        {
            trustLogger.Error("UserConfigLogManagementValidationSave", "Blocked", "Speichern wegen kritischem Loggrößenwert blockiert.", operationId);
            throw new InvalidOperationException($"Konfiguration enthält kritische Loggrößenwerte. Speichern wurde blockiert. {logManagementValidation.Summary}");
        }

        config.ConfigVersion = CurrentConfigVersion;
        var targetUserConfigPath = ResolveLanguageSpecificUserConfigPath(config);
        var existingUserConfig = File.Exists(targetUserConfigPath)
            ? DeserializeUserConfig(targetUserConfigPath)
            : (File.Exists(config.ConfigFilePath) ? DeserializeUserConfig(config.ConfigFilePath) : new UserConfigData());

        config.ConfigFilePath = targetUserConfigPath;
        var userConfig = ToUserConfig(config);
        Directory.CreateDirectory(Path.GetDirectoryName(config.ConfigFilePath)!);
        File.WriteAllText(config.ConfigFilePath, JsonSerializer.Serialize(userConfig, _jsonOptions));

        var persistedUserConfig = DeserializeUserConfig(config.ConfigFilePath);
        ApplyUserConfig(config, persistedUserConfig);
        MirrorLanguageToProgramConfig(config);

        LogLogVisibilityChanges(existingUserConfig.LogTabs, userConfig.LogTabs, config, operationId);
        if (existingUserConfig.ShortDestinationLogs != userConfig.ShortDestinationLogs)
        {
            var auditLogger = new AuditLogger(config);
            auditLogger.Info("ShortDestinationLogsChanged", $"shortDestinationLogs wurde von {existingUserConfig.ShortDestinationLogs} auf {userConfig.ShortDestinationLogs} geändert.", "-", "-", operationId);
        }

        var saveMessageParts = new List<string>();
        if (pathValidation.HasInformationalIssues)
        {
            saveMessageParts.Add(pathValidation.Summary);
        }
        if (timeIntervalValidation.HasHints)
        {
            saveMessageParts.Add(timeIntervalValidation.Summary);
        }
        if (logManagementValidation.HasInformationalIssues)
        {
            saveMessageParts.Add(logManagementValidation.Summary);
        }

        var hasSaveWarnings = saveMessageParts.Count > 0;
        if (hasSaveWarnings)
        {
            trustLogger.Warn("UserConfigSave", "AllowedWithWarnings", "Speichern mit Hinweiswerten in config.json erlaubt.", operationId);
        }
        else
        {
            trustLogger.Info("UserConfigSave", "Success", "Benutzerkonfiguration erfolgreich gespeichert.", operationId);
        }

        return new ConfigSaveResult
        {
            Saved = true,
            HasWarnings = hasSaveWarnings,
            Message = saveMessageParts.Count > 0 ? string.Join(Environment.NewLine + Environment.NewLine, saveMessageParts) : "Konfiguration erfolgreich gespeichert.",
            TrustedConfigRewritten = false,
            Validation = new TrustedConfigValidationResult()
        };
    }

    public ConfigSaveResult SaveTrustedConfiguration(AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.TrustedConfigFilePath))
        {
            throw new InvalidOperationException("TrustedConfigFilePath ist nicht gesetzt.");
        }

        var trustLogger = new TrustLogger(config.TrustLogPath, config);
        const string operationId = "TRUSTEDCONFIG-SAVE";
        var trustedConfig = ToTrustedConfig(config);
        var validation = _validator.ValidateForSave(config, trustedConfig);
        LogValidationEvents(trustLogger, validation, operationId);
        LogAllowListEvents(trustLogger, trustedConfig.AllowedSources, trustedConfig.AllowedDestinations, validation, operationId);

        var pathValidation = _pathValidator.ValidateForSave(config);
        LogPathValidationEvents(trustLogger, pathValidation, operationId, isStartup: false);

        var timeIntervalValidation = _timeIntervalValidator.ValidateForSave(config);
        var logManagementValidation = _logManagementValidator.ValidateForSave(config);
        LogTimeIntervalValidationEvents(trustLogger, timeIntervalValidation, operationId);
        LogLogManagementValidationEvents(trustLogger, logManagementValidation, operationId);

        if (validation.HasErrors)
        {
            config.TrustState = TrustState.Broken;
            config.IsSimulationModeEnforced = true;
            config.SimulationMode = true;
            ApplyValidationMetadata(config, validation);
            trustLogger.Error("TrustedConfigSave", "Blocked", "Speichern blockiert wegen Schema-/Konsistenzfehlern.", operationId);
            throw new InvalidOperationException($"TrustedConfig enthält Validierungsfehler. Speichern wurde blockiert. {validation.ValidationSummary}");
        }

        if (pathValidation.HasCriticalIssues)
        {
            trustLogger.Error("PathValidationSave", "Blocked", "Speichern wegen kritischem Pfadfehler blockiert.", operationId);
            throw new InvalidOperationException($"Konfiguration enthält kritische Pfadfehler. Speichern wurde blockiert. {pathValidation.Summary}");
        }

        if (timeIntervalValidation.HasCriticalIssues)
        {
            trustLogger.Error("TimeIntervalValidationSave", "Blocked", "Speichern wegen kritischem Zeit-/Intervallwert blockiert.", operationId);
            throw new InvalidOperationException($"Konfiguration enthält kritische Zeit- oder Intervallwerte. Speichern wurde blockiert. {timeIntervalValidation.Summary}");
        }

        if (logManagementValidation.HasCriticalIssues)
        {
            trustLogger.Error("LogManagementValidationSave", "Blocked", "Speichern wegen kritischem Loggrößenwert blockiert.", operationId);
            throw new InvalidOperationException($"Konfiguration enthält kritische Loggrößenwerte. Speichern wurde blockiert. {logManagementValidation.Summary}");
        }

        config.ConfigVersion = CurrentConfigVersion;
        Directory.CreateDirectory(Path.GetDirectoryName(config.TrustedConfigFilePath)!);
        File.WriteAllText(config.TrustedConfigFilePath, JsonSerializer.Serialize(trustedConfig, _jsonOptions));
        trustLogger.Info("AllowListSave", "Saved", $"Allow-Listen im Zustand {config.TrustState} gespeichert. Sources={string.Join(", ", trustedConfig.AllowedSources ?? [])}; Destinations={string.Join(", ", trustedConfig.AllowedDestinations ?? [])}", operationId);

        ApplyValidationMetadata(config, validation);
        config.TrustedConfigWasSavedUntrusted = true;
        config.TrustState = TrustState.NotTrusted;
        config.TrustResetRequested = true;
        config.LastSignatureValidation = "TrustedConfig wurde gespeichert, ist aber bis zur externen Neuerzeugung und Signierung des Catalogs nicht vertrauenswürdig.";
        config.LastTrustedSignerThumbprint = string.Empty;
        config.StartupSecurityBlockReason = config.LastSignatureValidation;
        config.IsSimulationModeEnforced = true;
        config.SimulationMode = true;

        var hasSaveWarnings = validation.HasWarnings || pathValidation.HasInformationalIssues || timeIntervalValidation.HasHints || logManagementValidation.HasInformationalIssues;
        if (hasSaveWarnings)
        {
            trustLogger.Warn("TrustedConfigSave", "AllowedWithWarnings", "TrustedConfig mit Warnungen gespeichert.", operationId);
        }
        else
        {
            trustLogger.Info("TrustedConfigSave", "Success", "TrustedConfig erfolgreich gespeichert.", operationId);
        }

        var saveMessageParts = new List<string>();
        if (validation.HasWarnings)
        {
            saveMessageParts.Add(validation.ValidationSummary);
        }
        if (pathValidation.HasInformationalIssues)
        {
            saveMessageParts.Add(pathValidation.Summary);
        }
        if (timeIntervalValidation.HasHints)
        {
            saveMessageParts.Add(timeIntervalValidation.Summary);
        }
        if (logManagementValidation.HasInformationalIssues)
        {
            saveMessageParts.Add(logManagementValidation.Summary);
        }

        InvalidateRuntimeTrustCache();

        return new ConfigSaveResult
        {
            Saved = true,
            HasWarnings = hasSaveWarnings,
            Message = saveMessageParts.Count > 0 ? string.Join(Environment.NewLine + Environment.NewLine, saveMessageParts) : "TrustedConfig erfolgreich gespeichert.",
            TrustedConfigRewritten = true,
            Validation = validation
        };
    }

    public ConfigSaveResult Save(AppConfig config)
    {
        var userResult = SaveUserConfiguration(config);
        if (config.TrustResetRequested)
        {
            var trustedResult = SaveTrustedConfiguration(config);
            return new ConfigSaveResult
            {
                Saved = userResult.Saved && trustedResult.Saved,
                HasWarnings = userResult.HasWarnings || trustedResult.HasWarnings,
                Message = string.Join(Environment.NewLine + Environment.NewLine, new[] { userResult.Message, trustedResult.Message }.Where(message => !string.IsNullOrWhiteSpace(message))),
                TrustedConfigRewritten = trustedResult.TrustedConfigRewritten,
                Validation = trustedResult.Validation
            };
        }

        return userResult;
    }

    public RuntimeTrustCheckResult RefreshRuntimeTrustState(AppConfig config, string operationId = "RUNTIME")
    {
        return RecheckTrustCore(config, operationId, logFailureAsProductiveBlock: false, forceFullValidation: false);
    }

    public RuntimeTrustCheckResult ForceRevalidateRuntimeTrustState(AppConfig config, string operationId = "RUNTIME-FORCE")
    {
        return RecheckTrustCore(config, operationId, logFailureAsProductiveBlock: false, forceFullValidation: true);
    }

    public ConfigurationBootstrapResult ReloadEffectiveConfiguration()
    {
        InvalidateRuntimeTrustCache();
        return EnsureAndLoad();
    }

    public RuntimeTrustCheckResult RefreshRuntimeTrustStateUsingFingerprintCachePreservingUserSettings(AppConfig config, string operationId = "RUNTIME-CACHE")
    {
        var probe = config.Clone();
        var result = RefreshRuntimeTrustStateUsingFingerprintCacheCore(probe, operationId);
        ApplyRuntimeSecurityState(config, probe);
        return result;
    }

    public RuntimeTrustCheckResult RefreshRuntimeTrustStatePreservingUserSettings(AppConfig config, string operationId = "RUNTIME")
    {
        var probe = config.Clone();
        var result = RecheckTrustCore(probe, operationId, logFailureAsProductiveBlock: false, forceFullValidation: false);
        ApplyRuntimeSecurityState(config, probe);
        return result;
    }

    public RuntimeTrustCheckResult ForceRevalidateRuntimeTrustStatePreservingUserSettings(AppConfig config, string operationId = "RUNTIME-FORCE")
    {
        var probe = config.Clone();
        var result = RecheckTrustCore(probe, operationId, logFailureAsProductiveBlock: false, forceFullValidation: true);
        ApplyRuntimeSecurityState(config, probe);
        return result;
    }

    private string ResolveLanguageSpecificUserConfigPath(AppConfig config)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appFolderName = GetLanguageDrivenAppFolderName(config.Language);
        return Path.Combine(roamingAppData, appFolderName, "config.json");
    }

    private UserConfigData DeserializeUserConfig(string userConfigPath)
    {
        var json = File.ReadAllText(userConfigPath);
        var userConfig = JsonSerializer.Deserialize<UserConfigData>(json, _jsonOptions) ?? new UserConfigData();
        ApplyLegacySuccessKeywords(userConfig, json);
        return userConfig;
    }

    private void MirrorLanguageToProgramConfig(AppConfig config)
    {
        try
        {
            var normalizedLanguage = string.IsNullOrWhiteSpace(config.Language) ? "Language-DEV" : config.Language.Trim();
            var programConfigPath = Path.Combine(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), "Config", "config.json");
            if (!File.Exists(programConfigPath))
            {
                return;
            }

            var programConfigJson = JsonNode.Parse(File.ReadAllText(programConfigPath))?.AsObject();
            if (programConfigJson is null)
            {
                return;
            }

            programConfigJson["Language"] = normalizedLanguage;
            programConfigJson["WindowTitle"] = config.WindowTitle;
            programConfigJson["AppDataFolderName"] = config.AppDataFolderName;
            programConfigJson["LocalLogDirectory"] = config.LocalLogDirectory;
            programConfigJson["LocalProcessingDirectory"] = config.LocalProcessingDirectory;
            File.WriteAllText(programConfigPath, programConfigJson.ToJsonString(_jsonOptions));
        }
        catch
        {
        }
    }

    private static void ApplyLegacySuccessKeywords(UserConfigData userConfig, string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (document.RootElement.TryGetProperty("SuccessKeywords", out _))
        {
            return;
        }

        if (!document.RootElement.TryGetProperty("PositiveKeywords", out var legacyKeywords) || legacyKeywords.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        userConfig.SuccessKeywords = legacyKeywords
            .EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item!)
            .ToArray();
    }

    private static ConfigPathValidationResult FilterUserPathValidation(ConfigPathValidationResult source)
    {
        var result = new ConfigPathValidationResult();
        foreach (var issue in source.Issues.Where(issue => string.Equals(issue.ConfigurationScope, "config.json", StringComparison.OrdinalIgnoreCase)))
        {
            result.Issues.Add(issue);
        }

        return result;
    }

    private static void ApplyUserConfig(AppConfig config, UserConfigData userConfig)
    {
        config.ConfigVersion = string.IsNullOrWhiteSpace(userConfig.ConfigVersion) ? CurrentConfigVersion : userConfig.ConfigVersion;
        config.WindowTitle = userConfig.WindowTitle;
        config.AppDataFolderName = userConfig.AppDataFolderName;
        config.LocalLogDirectory = userConfig.LocalLogDirectory;
        config.PsExecTimeoutSeconds = userConfig.PsExecTimeoutSeconds;
        config.ConnectionStatusIntervalSeconds = userConfig.ConnectionStatusIntervalSeconds;
        config.ConnectionTimeoutSeconds = userConfig.ConnectionTimeoutSeconds;
        config.LiveViewRefreshSeconds = userConfig.LiveViewRefreshSeconds;
        config.AutoRefreshTargetLogs = userConfig.AutoRefreshTargetLogs;
        config.FallbackTaskDelayMinutes = userConfig.FallbackTaskDelayMinutes;
        config.LocalProcessingDirectory = userConfig.LocalProcessingDirectory;
        config.DefaultLogFiles = userConfig.DefaultLogFiles;
        config.WarningKeywords = userConfig.WarningKeywords;
        config.ErrorKeywords = userConfig.ErrorKeywords;
        config.SuccessKeywords = userConfig.SuccessKeywords;
        config.LiveConnectionStatusMessage = userConfig.LiveConnectionStatusMessage;
        config.OptionsShowDefaultLogFiles = userConfig.OptionsShowDefaultLogFiles;
        config.Language = string.IsNullOrWhiteSpace(userConfig.Language) ? "Language-DEV" : userConfig.Language;
        config.ShortDestinationLogs = userConfig.ShortDestinationLogs;
        config.EnableAppLogRotation = userConfig.EnableAppLogRotation;
        config.MaxManagedLogSizeMb = userConfig.MaxManagedLogSizeMb;
        config.MaxManagedLogHistoryFiles = userConfig.MaxManagedLogHistoryFiles;
        config.MaxKeptLocalLogs = userConfig.MaxKeptLocalLogs;
        config.SimulationMode = config.IsSimulationModeEnforced ? true : userConfig.SimulationMode;
        config.LogTabs = userConfig.LogTabs ?? new LogTabVisibilityConfig();
    }

    private static void ApplyRuntimeSecurityState(AppConfig targetConfig, AppConfig sourceConfig)
    {
        targetConfig.TrustState = sourceConfig.TrustState;
        targetConfig.LastSignatureValidation = sourceConfig.LastSignatureValidation;
        targetConfig.LastTrustedSignerThumbprint = sourceConfig.LastTrustedSignerThumbprint;
        targetConfig.LastSchemaValidation = sourceConfig.LastSchemaValidation;
        targetConfig.LastConsistencyValidation = sourceConfig.LastConsistencyValidation;
        targetConfig.ValidationSummary = sourceConfig.ValidationSummary;
        targetConfig.ValidationErrorCount = sourceConfig.ValidationErrorCount;
        targetConfig.ValidationWarningCount = sourceConfig.ValidationWarningCount;
        targetConfig.ValidationInfoCount = sourceConfig.ValidationInfoCount;
        targetConfig.IsSimulationModeEnforced = sourceConfig.IsSimulationModeEnforced;
        targetConfig.TrustedConfigWasSavedUntrusted = sourceConfig.TrustedConfigWasSavedUntrusted;
        targetConfig.TrustResetRequested = sourceConfig.TrustResetRequested;
        targetConfig.StartupSecurityBlockReason = sourceConfig.StartupSecurityBlockReason;
        if (sourceConfig.IsSimulationModeEnforced)
        {
            targetConfig.SimulationMode = true;
        }
    }

    private RuntimeTrustCheckResult RefreshRuntimeTrustStateUsingFingerprintCacheCore(AppConfig config, string operationId)
    {
        var trustLogger = new TrustLogger(config.TrustLogPath, config);

        if (string.IsNullOrWhiteSpace(config.TrustedConfigFilePath) || !File.Exists(config.TrustedConfigFilePath))
        {
            const string message = "TrustedConfig-Fingerprint-Prüfung nicht möglich, weil TrustedConfig.json fehlt. Produktiver Modus bleibt blockiert.";
            config.TrustState = TrustState.NotTrusted;
            config.IsSimulationModeEnforced = true;
            config.SimulationMode = true;
            config.LastSignatureValidation = message;
            config.ValidationSummary = message;
            config.StartupSecurityBlockReason = message;
            trustLogger.Warn("TrustedConfigFingerprintRefresh", "Failed", message, operationId);
            InvalidateRuntimeTrustCache();
            return new RuntimeTrustCheckResult { Allowed = false, Message = message, SessionShouldClose = true, SourceHost = Environment.MachineName, DestinationHost = string.Empty };
        }

        var executableDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var trustedCatalogPath = Path.Combine(executableDirectory, "catalog", "TrustedConfig.cat");
        var cacheKey = BuildRuntimeTrustCacheKey(config);
        if (TryGetRuntimeTrustCache(cacheKey, config, out var cachedResult))
        {
            config.StartupSecurityBlockReason = string.Empty;
            trustLogger.Info("TrustedConfigFingerprintRefresh", "Cached", "Trusted-Zustand aus gültigem Fingerprint-Cache wiederverwendet.", operationId);
            return cachedResult;
        }

        var fingerprintChanged = !File.Exists(trustedCatalogPath)
            ? "TrustedConfig.cat fehlt oder ist nicht erreichbar."
            : "TrustedConfig-Fingerprint weicht vom letzten validierten Cache ab oder der Cache ist nicht mehr vorhanden.";
        var cacheMismatchMessage = $"{fingerprintChanged} Bitte Trust neu validieren oder die App neu starten. Bis dahin bleibt der produktive Modus blockiert.";

        config.TrustState = config.TrustState == TrustState.Broken ? TrustState.Broken : TrustState.NotTrusted;
        config.IsSimulationModeEnforced = true;
        config.SimulationMode = true;
        config.LastSignatureValidation = cacheMismatchMessage;
        config.StartupSecurityBlockReason = cacheMismatchMessage;
        if (string.IsNullOrWhiteSpace(config.ValidationSummary) || string.Equals(config.ValidationSummary, "Trusted", StringComparison.OrdinalIgnoreCase))
        {
            config.ValidationSummary = cacheMismatchMessage;
        }

        trustLogger.Warn("TrustedConfigFingerprintRefresh", "Blocked", cacheMismatchMessage, operationId);
        InvalidateRuntimeTrustCache();
        return new RuntimeTrustCheckResult { Allowed = false, Message = cacheMismatchMessage, SessionShouldClose = true, SourceHost = Environment.MachineName, DestinationHost = string.Empty };
    }

    public RuntimeTrustCheckResult RecheckBeforeProductiveAction(AppConfig config, string actionName, string targetDeviceName)
    {
        var operationId = $"ACTION-{actionName.ToUpperInvariant().Replace(' ', '-')}";
        var trustResult = RecheckTrustCore(config, operationId, logFailureAsProductiveBlock: true, forceFullValidation: false);
        if (!trustResult.Allowed)
        {
            return trustResult;
        }

        return EnforceAllowedSystems(config, actionName, targetDeviceName, operationId);
    }

    private RuntimeTrustCheckResult RecheckTrustCore(AppConfig config, string operationId, bool logFailureAsProductiveBlock, bool forceFullValidation)
    {
        var trustLogger = new TrustLogger(config.TrustLogPath, config);
        using var perf = PerformanceTrace.Start(trustLogger, forceFullValidation ? "RuntimeTrustFullValidation" : "RuntimeTrustRecheck", operationId, nameof(ConfigBootstrapper));
        trustLogger.Info("TrustedConfigRecheck", "Started", forceFullValidation ? "Vollständige Revalidierung der TrustedConfig gestartet." : "Lightweight-Recheck der TrustedConfig gestartet.", operationId);

        if (string.IsNullOrWhiteSpace(config.TrustedConfigFilePath) || !File.Exists(config.TrustedConfigFilePath))
        {
            config.TrustState = TrustState.Broken;
            config.IsSimulationModeEnforced = true;
            config.SimulationMode = true;
            var message = "TrustedConfig.json fehlt beim Recheck. Produktive Aktionen bleiben blockiert.";
            trustLogger.Error("TrustedConfigRecheck", "Failed", message, operationId);
            if (logFailureAsProductiveBlock)
            {
                trustLogger.Error("ProductiveActionRecheck", "Failed", "Recheck vor produktiver Aktion fehlgeschlagen.", operationId);
            }
            return new RuntimeTrustCheckResult { Allowed = false, Message = message };
        }

        var executableDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var trustedCatalogPath = Path.Combine(executableDirectory, "catalog", "TrustedConfig.cat");
        if (!File.Exists(trustedCatalogPath))
        {
            config.TrustState = TrustState.NotTrusted;
            config.IsSimulationModeEnforced = true;
            config.SimulationMode = true;
            var message = "TrustedConfig.cat fehlt beim Recheck. Produktive Aktionen bleiben blockiert.";
            trustLogger.Warn("TrustedConfigRecheck", "Failed", message, operationId);
            if (logFailureAsProductiveBlock)
            {
                trustLogger.Error("ProductiveActionRecheck", "Failed", "Recheck vor produktiver Aktion fehlgeschlagen.", operationId);
            }
            return new RuntimeTrustCheckResult { Allowed = false, Message = message };
        }

        var cacheKey = BuildRuntimeTrustCacheKey(config);
        RuntimeTrustCheckResult cachedResult = new RuntimeTrustCheckResult();
        if (!forceFullValidation && TryGetRuntimeTrustCache(cacheKey, config, out cachedResult))
        {
            trustLogger.Info("TrustedConfigRecheck", "Cached", "Trusted-Zustand aus gültigem Fingerprint-Cache wiederverwendet.", operationId);
            return cachedResult;
        }

        var userConfig = ToUserConfig(config);
        var validationContext = _validator.LoadAndValidateFromDisk(config.TrustedConfigFilePath, userConfig, config.TrustedConfigPath, config.TrustLogPath);
        LogValidationEvents(trustLogger, validationContext.Validation, operationId);
        LogAllowListEvents(trustLogger, validationContext.RuntimeConfig.AllowedSources, validationContext.RuntimeConfig.AllowedDestinations, validationContext.Validation, operationId);

        var verifier = new AuthentiCodeVerifier();
        var catalogVerifier = new FileCatalogVerifier();
        var exePath = Environment.ProcessPath ?? Path.Combine(executableDirectory, "DapIntuneSupportSuite.exe");
        var exeSignature = verifier.Verify(exePath);
        var trustedCatalogSignature = verifier.Verify(trustedCatalogPath);
        var catalogMatch = catalogVerifier.Verify(trustedCatalogPath, config.TrustedConfigFilePath);
        var sameSigner = trustedCatalogSignature.Success && exeSignature.Success &&
                         !string.IsNullOrWhiteSpace(trustedCatalogSignature.Thumbprint) &&
                         !string.IsNullOrWhiteSpace(exeSignature.Thumbprint) &&
                         string.Equals(trustedCatalogSignature.Thumbprint, exeSignature.Thumbprint, StringComparison.OrdinalIgnoreCase) &&
                         string.Equals(trustedCatalogSignature.PublicKey, exeSignature.PublicKey, StringComparison.Ordinal);

        var aclValid = CheckTrustedDirectoryAcl(Path.GetDirectoryName(config.TrustedConfigFilePath)!);
        var trustState = DetermineTrustState(trustedCatalogSignature, catalogMatch, sameSigner, validationContext.Validation, aclValid);

        config.RemoteAuditLogDirectory = validationContext.RuntimeConfig.RemoteAuditLogDirectory;
        config.RemoteImeLogDirectory = validationContext.RuntimeConfig.RemoteImeLogDirectory;
        config.RemoteTempDirectory = validationContext.RuntimeConfig.RemoteTempDirectory;
        config.SupportClientDirectory = validationContext.RuntimeConfig.SupportClientDirectory;
        config.PowerShellExecutable = validationContext.RuntimeConfig.PowerShellExecutable;
        config.PsExecPath = validationContext.RuntimeConfig.PsExecPath;
        config.ToolsDirectoryPath = validationContext.RuntimeConfig.ToolsDirectoryPath;
        config.PsExecCatalogFilePath = validationContext.RuntimeConfig.PsExecCatalogFilePath;
        config.EnablePsExecCatalogValidation = validationContext.RuntimeConfig.EnablePsExecCatalogValidation;
        config.PsExecExpectedSigner = validationContext.RuntimeConfig.PsExecExpectedSigner;
        config.PsExecExpectedThumbprint = validationContext.RuntimeConfig.PsExecExpectedThumbprint;
        config.PsExecExpectedPublicKey = validationContext.RuntimeConfig.PsExecExpectedPublicKey;
        config.PsExecDownloadSource = validationContext.RuntimeConfig.PsExecDownloadSource;
        config.LatestPublishedPsExecVersion = validationContext.RuntimeConfig.LatestPublishedPsExecVersion;
        config.LocalPsExecVersion = validationContext.RuntimeConfig.LocalPsExecVersion;
        config.PsExecVersionStatus = validationContext.RuntimeConfig.PsExecVersionStatus;
        config.LastPsExecVersionCheck = validationContext.RuntimeConfig.LastPsExecVersionCheck;
        config.LastDownloadSource = validationContext.RuntimeConfig.LastDownloadSource;
        config.LastDownloadValidationResult = validationContext.RuntimeConfig.LastDownloadValidationResult;
        config.FallbackConfigFileName = validationContext.RuntimeConfig.FallbackConfigFileName;
        config.FallbackScriptFileName = validationContext.RuntimeConfig.FallbackScriptFileName;
        config.FallbackScheduledTaskName = validationContext.RuntimeConfig.FallbackScheduledTaskName;
        config.FallbackRunOnceValueName = validationContext.RuntimeConfig.FallbackRunOnceValueName;
        config.RemoteFallbackLogFileName = validationContext.RuntimeConfig.RemoteFallbackLogFileName;
        config.ConnectionFallback = validationContext.RuntimeConfig.ConnectionFallback;
        config.RestoreRemotingState = validationContext.RuntimeConfig.RestoreRemotingState;
        config.RegistryPathsForAppReset = validationContext.RuntimeConfig.RegistryPathsForAppReset;
        config.ImeServiceName = validationContext.RuntimeConfig.ImeServiceName;
        config.AllowedSources = validationContext.RuntimeConfig.AllowedSources;
        config.AllowedDestinations = validationContext.RuntimeConfig.AllowedDestinations;
        ApplyValidationMetadata(config, validationContext.Validation);
        config.TrustState = trustState;
        config.StartupSecurityBlockReason = string.Empty;
        config.IsSimulationModeEnforced = trustState != TrustState.Trusted;
        if (config.IsSimulationModeEnforced)
        {
            config.SimulationMode = true;
        }

        config.LastSignatureValidation = trustState == TrustState.Trusted
            ? "TrustedConfig.cat ist gültig signiert, passt zu TrustedConfig.json und der Signer stimmt mit der EXE überein."
            : string.IsNullOrWhiteSpace(catalogMatch.StatusMessage) ? trustedCatalogSignature.StatusMessage : catalogMatch.StatusMessage;
        config.LastTrustedSignerThumbprint = trustedCatalogSignature.Thumbprint;

        if (trustState == TrustState.Trusted)
        {
            trustLogger.Info("TrustedConfigRecheck", "Success", config.ValidationSummary, operationId);
            trustLogger.Info("TrustedConfigConsistentState", "Trusted", "Wiedererkennung eines konsistenten Trusted-Zustands.", operationId);
            var successResult = new RuntimeTrustCheckResult { Allowed = true, Message = config.ValidationSummary, SourceHost = Environment.MachineName, DestinationHost = string.Empty };
            StoreRuntimeTrustCache(cacheKey, config, successResult);
            return successResult;
        }

        var blockedMessage = trustState == TrustState.Broken
            ? $"TrustedConfig ist fehlerhaft. {config.ValidationSummary}"
            : string.IsNullOrWhiteSpace(catalogMatch.StatusMessage)
                ? "TrustedConfig ist nicht vertrauenswürdig. Produktive Aktionen bleiben blockiert."
                : catalogMatch.StatusMessage;

        trustLogger.Warn("TrustedConfigRecheck", trustState.ToString(), blockedMessage, operationId);
        if (logFailureAsProductiveBlock)
        {
            trustLogger.Error("ProductiveActionRecheck", "Failed", "Recheck vor produktiver Aktion fehlgeschlagen.", operationId);
        }

        config.StartupSecurityBlockReason = blockedMessage;
        var blockedResult = new RuntimeTrustCheckResult { Allowed = false, Message = blockedMessage, SessionShouldClose = true, SourceHost = Environment.MachineName, DestinationHost = string.Empty };
        InvalidateRuntimeTrustCache();
        return blockedResult;
    }

    private void LogLogVisibilityChanges(LogTabVisibilityConfig previous, LogTabVisibilityConfig current, AppConfig config, string operationId)
    {
        var auditLogger = new AuditLogger(config);
        foreach (var change in EnumerateLogTabChanges(previous, current))
        {
            auditLogger.Info(
                "LogVisibilityChanged",
                $"Log '{change.Name}' ({change.Scope}) wurde von {change.OldValue} auf {change.NewValue} geändert.",
                "-",
                "-",
                operationId);
        }
    }

    private static IEnumerable<(string Name, string Scope, bool OldValue, bool NewValue)> EnumerateLogTabChanges(LogTabVisibilityConfig previous, LogTabVisibilityConfig current)
    {
        foreach (var item in GetLogTabDefinitions(previous, current))
        {
            if (item.OldValue != item.NewValue)
            {
                yield return item;
            }
        }
    }

    private static IEnumerable<(string Name, string Scope, bool OldValue, bool NewValue)> GetLogTabDefinitions(LogTabVisibilityConfig previous, LogTabVisibilityConfig current)
    {
        yield return ("DAP Intune Support", "local", previous.LocalAppLog.IsVisible, current.LocalAppLog.IsVisible);
        yield return ("Log Verlauf", "local", previous.AppDataLogs.IsVisible, current.AppDataLogs.IsVisible);
        yield return ("Trust Log", "local", previous.TrustLog.IsVisible, current.TrustLog.IsVisible);
        yield return ("DAP Remote Audit Log", "remote", previous.RemoteAuditLog.IsVisible, current.RemoteAuditLog.IsVisible);
        yield return ("DAP Fallback Log", "remote", previous.FallbackLog.IsVisible, current.FallbackLog.IsVisible);
        yield return ("AgentExecutor", "remote", previous.AgentExecutor.IsVisible, current.AgentExecutor.IsVisible);
        yield return ("AppActionProcessor", "remote", previous.AppActionProcessor.IsVisible, current.AppActionProcessor.IsVisible);
        yield return ("AppWorkload", "remote", previous.AppWorkload.IsVisible, current.AppWorkload.IsVisible);
        yield return ("ClientCertCheck", "remote", previous.ClientCertCheck.IsVisible, current.ClientCertCheck.IsVisible);
        yield return ("ClientHealth", "remote", previous.ClientHealth.IsVisible, current.ClientHealth.IsVisible);
        yield return ("DeviceHealthMonitoring", "remote", previous.DeviceHealthMonitoring.IsVisible, current.DeviceHealthMonitoring.IsVisible);
        yield return ("HealthScripts", "remote", previous.HealthScripts.IsVisible, current.HealthScripts.IsVisible);
        yield return ("IntuneManagementExtension", "remote", previous.IntuneManagementExtension.IsVisible, current.IntuneManagementExtension.IsVisible);
        yield return ("NotificationInfraLogs", "remote", previous.NotificationInfraLogs.IsVisible, current.NotificationInfraLogs.IsVisible);
        yield return ("Sensor", "remote", previous.Sensor.IsVisible, current.Sensor.IsVisible);
        yield return ("Win321AppInventory", "remote", previous.Win321AppInventory.IsVisible, current.Win321AppInventory.IsVisible);
    }

    private RuntimeTrustCheckResult EnforceAllowedSystems(AppConfig config, string actionName, string targetDeviceName, string operationId)
    {
        var trustLogger = new TrustLogger(config.TrustLogPath, config);
        var sourceHost = Environment.MachineName;

        trustLogger.Info("AllowedSourcesCheck", "Started", $"Prüfung von AllowedSources für Quellsystem '{sourceHost}' gestartet.", operationId, sourceHost, targetDeviceName, actionName);
        var sourceResult = EnforceAllowedSource(config, actionName, sourceHost, targetDeviceName, operationId, trustLogger);
        if (!sourceResult.Allowed)
        {
            return sourceResult;
        }

        trustLogger.Info("AllowedDestinationsCheck", "Started", $"Prüfung von AllowedDestinations für Zielsystem '{targetDeviceName}' gestartet.", operationId, sourceHost, targetDeviceName, actionName);
        return EnforceAllowedDestination(config, actionName, sourceHost, targetDeviceName, operationId, trustLogger);
    }

    private RuntimeTrustCheckResult EnforceAllowedSource(AppConfig config, string actionName, string sourceHost, string targetDeviceName, string operationId, TrustLogger trustLogger)
    {
        var sourceContext = BuildSourceAllowContext(sourceHost);
        var allowedSources = config.AllowedSources ?? [];
        if (allowedSources.Length == 0)
        {
            const string message = "AllowedSources ist leer und wird als 'alles erlaubt' interpretiert.";
            trustLogger.Info("AllowedSourcesCheck", "AllAllowed", message, operationId, sourceHost, targetDeviceName, actionName, sourceContext.IpAddresses, null, "*");
            return new RuntimeTrustCheckResult
            {
                Allowed = true,
                Message = message,
                SourceHost = sourceContext.DisplayHost,
                SourceIps = sourceContext.IpAddresses,
                DestinationHost = targetDeviceName
            };
        }

        var match = EvaluateAllowMatch(sourceContext, allowedSources, resolveRequiredForIpChecks: false);
        if (!match.Allowed)
        {
            var message = $"Quellsystem '{sourceContext.DisplayHost}' ist nicht durch AllowedSources erlaubt. Produktive Aktion wurde blockiert.";
            trustLogger.Warn("AllowedSourcesCheck", "Blocked", message, operationId, sourceContext.DisplayHost, targetDeviceName, actionName, sourceContext.IpAddresses);
            trustLogger.Error("ProductiveActionSourceBlocked", "Blocked", $"Produktive Aktion '{actionName}' wegen nicht erlaubtem Quellsystem blockiert. Source={sourceContext.DisplayHost}; AllowedSources={string.Join(", ", allowedSources)}", operationId, sourceContext.DisplayHost, targetDeviceName, actionName, sourceContext.IpAddresses);
            return new RuntimeTrustCheckResult
            {
                Allowed = false,
                Message = message,
                SessionShouldClose = true,
                SourceHost = sourceContext.DisplayHost,
                SourceIps = sourceContext.IpAddresses,
                DestinationHost = targetDeviceName,
                MatchedAllowEntry = string.Empty
            };
        }

        trustLogger.Info("AllowedSourcesCheck", "Success", $"Quellsystem '{sourceContext.DisplayHost}' ist erlaubt. Match='{match.MatchedEntry}'. {match.MatchDescription}", operationId, sourceContext.DisplayHost, targetDeviceName, actionName, sourceContext.IpAddresses, null, match.MatchedEntry);
        return new RuntimeTrustCheckResult
        {
            Allowed = true,
            Message = $"Quellsystem '{sourceContext.DisplayHost}' ist erlaubt.",
            SourceHost = sourceContext.DisplayHost,
            SourceIps = sourceContext.IpAddresses,
            DestinationHost = targetDeviceName,
            MatchedAllowEntry = match.MatchedEntry
        };
    }

    private RuntimeTrustCheckResult EnforceAllowedDestination(AppConfig config, string actionName, string sourceHost, string targetDeviceName, string operationId, TrustLogger trustLogger)
    {
        if (string.IsNullOrWhiteSpace(targetDeviceName))
        {
            const string message = "Kein Zielsystem angegeben. Produktive Aktion bleibt blockiert.";
            trustLogger.Warn("AllowedDestinationsCheck", "Blocked", message, operationId, sourceHost, targetDeviceName, actionName);
            trustLogger.Error("ProductiveActionTargetBlocked", "Blocked", $"Produktive Aktion '{actionName}' wurde ohne Zielsystem blockiert.", operationId, sourceHost, targetDeviceName, actionName);
            return new RuntimeTrustCheckResult { Allowed = false, Message = message, SessionShouldClose = true, SourceHost = sourceHost, DestinationHost = targetDeviceName };
        }

        var destinationContext = BuildDestinationAllowContext(targetDeviceName);
        var allowedDestinations = config.AllowedDestinations ?? [];
        if (allowedDestinations.Length == 0)
        {
            const string message = "AllowedDestinations ist leer und wird als 'alles erlaubt' interpretiert.";
            trustLogger.Info("AllowedDestinationsCheck", "AllAllowed", message, operationId, sourceHost, destinationContext.DisplayHost, actionName, null, destinationContext.IpAddresses, "*");
            return new RuntimeTrustCheckResult
            {
                Allowed = true,
                Message = message,
                SourceHost = sourceHost,
                DestinationHost = destinationContext.DisplayHost,
                DestinationIps = destinationContext.IpAddresses
            };
        }

        var match = EvaluateAllowMatch(destinationContext, allowedDestinations, resolveRequiredForIpChecks: true);
        if (!match.Allowed)
        {
            var message = destinationContext.ResolutionFailed && string.IsNullOrWhiteSpace(match.MatchedEntry)
                ? $"Zielsystem '{destinationContext.DisplayHost}' konnte nicht für einen IP-/CIDR-Abgleich aufgelöst werden und ist nicht explizit per Hostname/FQDN erlaubt. Produktive Aktion wurde blockiert."
                : $"Zielsystem '{destinationContext.DisplayHost}' ist nicht durch AllowedDestinations erlaubt. Produktive Aktion wurde blockiert.";
            if (destinationContext.ResolutionFailed)
            {
                trustLogger.Warn("AllowedDestinationResolution", "Failed", destinationContext.ResolutionMessage, operationId, sourceHost, destinationContext.DisplayHost, actionName, null, destinationContext.IpAddresses);
                trustLogger.Warn("AllowedDestinationsResolutionBlocked", "Blocked", message, operationId, sourceHost, destinationContext.DisplayHost, actionName, null, destinationContext.IpAddresses);
            }
            else
            {
                trustLogger.Warn("AllowedDestinationsCheck", "Blocked", message, operationId, sourceHost, destinationContext.DisplayHost, actionName, null, destinationContext.IpAddresses);
            }

            trustLogger.Error("ProductiveActionTargetBlocked", "Blocked", $"Produktive Aktion '{actionName}' wegen nicht erlaubtem Zielsystem blockiert. Ziel={destinationContext.DisplayHost}; AllowedDestinations={string.Join(", ", allowedDestinations)}", operationId, sourceHost, destinationContext.DisplayHost, actionName, null, destinationContext.IpAddresses);
            return new RuntimeTrustCheckResult
            {
                Allowed = false,
                Message = message,
                SessionShouldClose = true,
                SourceHost = sourceHost,
                DestinationHost = destinationContext.DisplayHost,
                DestinationIps = destinationContext.IpAddresses,
                MatchedAllowEntry = string.Empty
            };
        }

        trustLogger.Info("AllowedDestinationsCheck", "Success", $"Zielsystem '{destinationContext.DisplayHost}' ist erlaubt. Match='{match.MatchedEntry}'. {match.MatchDescription}", operationId, sourceHost, destinationContext.DisplayHost, actionName, null, destinationContext.IpAddresses, match.MatchedEntry);
        return new RuntimeTrustCheckResult
        {
            Allowed = true,
            Message = $"Zielsystem '{destinationContext.DisplayHost}' ist erlaubt.",
            SourceHost = sourceHost,
            DestinationHost = destinationContext.DisplayHost,
            DestinationIps = destinationContext.IpAddresses,
            MatchedAllowEntry = match.MatchedEntry
        };
    }

    private static void LogAllowListEvents(TrustLogger trustLogger, IEnumerable<string>? allowedSources, IEnumerable<string>? allowedDestinations, TrustedConfigValidationResult validation, string operationId)
    {
        LogSingleAllowListEvents(trustLogger, "AllowedSources", allowedSources, validation, "ALLOWEDSOURCES", operationId);
        LogSingleAllowListEvents(trustLogger, "AllowedDestinations", allowedDestinations, validation, "ALLOWEDDESTINATIONS", operationId);
    }

    private static void LogSingleAllowListEvents(TrustLogger trustLogger, string listName, IEnumerable<string>? values, TrustedConfigValidationResult validation, string issueCodeToken, string operationId)
    {
        var normalizedValues = values?.Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value.Trim()).ToArray() ?? [];
        trustLogger.Info($"{listName}Load", "Loaded", $"{listName} aus TrustedConfig geladen. Anzahl Einträge={normalizedValues.Length}; Einträge={string.Join(", ", normalizedValues)}", operationId);

        if (normalizedValues.Length == 0)
        {
            trustLogger.Info($"{listName}Semantics", "AllAllowed", $"{listName} ist leer und wird als 'alles erlaubt' interpretiert.", operationId);
        }

        var listIssues = validation.AllIssues
            .Where(issue => issue.Code.Contains(issueCodeToken, StringComparison.OrdinalIgnoreCase) || issue.Code.Contains("ALLOWEDJUMPHOSTS", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        var schemaIssues = listIssues.Where(issue => validation.SchemaIssues.Contains(issue)).ToArray();
        if (schemaIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
        {
            trustLogger.Error($"{listName}SchemaValidation", "Failed", string.Join(" | ", schemaIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else if (schemaIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Warning))
        {
            trustLogger.Warn($"{listName}SchemaValidation", "Warnings", string.Join(" | ", schemaIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else
        {
            trustLogger.Info($"{listName}SchemaValidation", "Success", $"Schema-Validierung für {listName} erfolgreich (Host/FQDN, IPv4 und CIDR unterstützt).", operationId);
        }

        var consistencyIssues = listIssues.Where(issue => validation.ConsistencyIssues.Contains(issue)).ToArray();
        if (consistencyIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
        {
            trustLogger.Error($"{listName}ConsistencyValidation", "Failed", string.Join(" | ", consistencyIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else if (consistencyIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Warning))
        {
            trustLogger.Warn($"{listName}ConsistencyValidation", "Warnings", string.Join(" | ", consistencyIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else if (consistencyIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Info))
        {
            trustLogger.Info($"{listName}ConsistencyValidation", "Info", string.Join(" | ", consistencyIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else
        {
            trustLogger.Info($"{listName}ConsistencyValidation", "Success", $"Konsistenz-Validierung für {listName} erfolgreich (Host/FQDN, IPv4 und CIDR unterstützt).", operationId);
        }
    }

    private static bool HasAllowListErrors(TrustedConfigValidationResult validation)
        => validation.AllIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error && (
            issue.Code.Contains("ALLOWEDSOURCES", StringComparison.OrdinalIgnoreCase) ||
            issue.Code.Contains("ALLOWEDDESTINATIONS", StringComparison.OrdinalIgnoreCase) ||
            issue.Code.Contains("ALLOWEDJUMPHOSTS", StringComparison.OrdinalIgnoreCase)));

    private static AllowContext BuildSourceAllowContext(string sourceHost)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(sourceHost))
        {
            names.Add(sourceHost.Trim());
        }

        try
        {
            var hostName = Dns.GetHostName();
            if (!string.IsNullOrWhiteSpace(hostName))
            {
                names.Add(hostName.Trim());
                var hostEntry = Dns.GetHostEntry(hostName);
                if (!string.IsNullOrWhiteSpace(hostEntry.HostName))
                {
                    names.Add(hostEntry.HostName.Trim());
                }

                foreach (var address in hostEntry.AddressList.Where(address => address.AddressFamily == AddressFamily.InterNetwork))
                {
                    ips.Add(address.ToString());
                }
            }
        }
        catch
        {
            // Best effort only.
        }

        return new AllowContext
        {
            DisplayHost = !string.IsNullOrWhiteSpace(sourceHost) ? sourceHost.Trim() : Environment.MachineName,
            HostNames = names.ToArray(),
            IpAddresses = ips.ToArray(),
            ResolutionAttempted = true,
            ResolutionFailed = false,
            ResolutionMessage = string.Empty
        };
    }

    private static AllowContext BuildDestinationAllowContext(string targetDeviceName)
    {
        var normalizedTarget = targetDeviceName.Trim();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { normalizedTarget };
        var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (IPAddress.TryParse(normalizedTarget, out var directAddress) && directAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            ips.Add(directAddress.ToString());
            return new AllowContext
            {
                DisplayHost = normalizedTarget,
                HostNames = names.ToArray(),
                IpAddresses = ips.ToArray(),
                ResolutionAttempted = false,
                ResolutionFailed = false,
                ResolutionMessage = string.Empty
            };
        }

        try
        {
            var hostEntry = Dns.GetHostEntry(normalizedTarget);
            if (!string.IsNullOrWhiteSpace(hostEntry.HostName))
            {
                names.Add(hostEntry.HostName.Trim());
            }

            foreach (var address in hostEntry.AddressList.Where(address => address.AddressFamily == AddressFamily.InterNetwork))
            {
                ips.Add(address.ToString());
            }

            return new AllowContext
            {
                DisplayHost = normalizedTarget,
                HostNames = names.ToArray(),
                IpAddresses = ips.ToArray(),
                ResolutionAttempted = true,
                ResolutionFailed = false,
                ResolutionMessage = string.Empty
            };
        }
        catch (Exception ex)
        {
            return new AllowContext
            {
                DisplayHost = normalizedTarget,
                HostNames = names.ToArray(),
                IpAddresses = ips.ToArray(),
                ResolutionAttempted = true,
                ResolutionFailed = true,
                ResolutionMessage = $"Zielauflösung für '{normalizedTarget}' fehlgeschlagen: {ex.Message}"
            };
        }
    }

    private static AllowMatchInfo EvaluateAllowMatch(AllowContext context, IEnumerable<string> allowList, bool resolveRequiredForIpChecks)
    {
        var normalizedEntries = allowList.Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value.Trim()).ToArray();

        foreach (var entry in normalizedEntries)
        {
            if (MatchesHostAllowEntry(context.HostNames, entry))
            {
                return new AllowMatchInfo { Allowed = true, MatchedEntry = entry, MatchDescription = entry.Contains('*') || entry.Contains('?') ? "Match über Host/FQDN-Wildcard." : "Match über Hostname/FQDN." };
            }
        }

        if (resolveRequiredForIpChecks && context.ResolutionFailed && context.IpAddresses.Length == 0)
        {
            return new AllowMatchInfo { Allowed = false, MatchDescription = context.ResolutionMessage };
        }

        foreach (var entry in normalizedEntries)
        {
            if (TryMatchIpOrCidr(context.IpAddresses, entry, out var description))
            {
                return new AllowMatchInfo { Allowed = true, MatchedEntry = entry, MatchDescription = description };
            }
        }

        return new AllowMatchInfo { Allowed = false, MatchDescription = context.ResolutionMessage };
    }

    private static bool MatchesHostAllowEntry(IEnumerable<string> candidateNames, string entry)
    {
        foreach (var candidate in candidateNames.Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value.Trim()))
        {
            if (string.Equals(candidate, entry, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (entry.Contains('*') || entry.Contains('?'))
            {
                var regexPattern = "^" + Regex.Escape(entry).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
                if (Regex.IsMatch(candidate, regexPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryMatchIpOrCidr(IEnumerable<string> ipAddresses, string entry, out string description)
    {
        description = string.Empty;
        var ipList = ipAddresses.Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value.Trim()).ToArray();
        if (ipList.Length == 0)
        {
            return false;
        }

        if (TryParseCidr(entry, out var network, out var mask))
        {
            foreach (var ip in ipList)
            {
                if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }

                if ((ToUInt32(address) & mask) == network)
                {
                    description = "Match über CIDR-Range.";
                    return true;
                }
            }

            return false;
        }

        if (IPAddress.TryParse(entry, out var allowedIp) && allowedIp.AddressFamily == AddressFamily.InterNetwork)
        {
            foreach (var ip in ipList)
            {
                if (string.Equals(ip, allowedIp.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    description = "Match über einzelne IPv4-Adresse.";
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryParseCidr(string entry, out uint network, out uint mask)
    {
        network = 0;
        mask = 0;
        var parts = entry.Split('/');
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        if (!int.TryParse(parts[1], out var prefixLength) || prefixLength < 0 || prefixLength > 32)
        {
            return false;
        }

        mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        network = ToUInt32(address) & mask;
        return true;
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private sealed class AllowContext
    {
        public string DisplayHost { get; init; } = string.Empty;
        public string[] HostNames { get; init; } = [];
        public string[] IpAddresses { get; init; } = [];
        public bool ResolutionAttempted { get; init; }
        public bool ResolutionFailed { get; init; }
        public string ResolutionMessage { get; init; } = string.Empty;
    }

    private sealed class AllowMatchInfo
    {
        public bool Allowed { get; init; }
        public string MatchedEntry { get; init; } = string.Empty;
        public string MatchDescription { get; init; } = string.Empty;
    }

    private static void ApplyValidationMetadata(AppConfig config, TrustedConfigValidationResult validation)
    {
        config.LastSchemaValidation = validation.LastSchemaValidation;
        config.LastConsistencyValidation = validation.LastConsistencyValidation;
        config.ValidationSummary = validation.ValidationSummary;
        config.ValidationErrorCount = validation.ErrorCount;
        config.ValidationWarningCount = validation.WarningCount;
        config.ValidationInfoCount = validation.InfoCount;
    }


    private static void LogLogManagementValidationEvents(TrustLogger trustLogger, LogManagementValidationResult validationResult, string operationId)
    {
        trustLogger.Info("LogManagementValidation", "Started", "Start der Loggrößenvalidierung.", operationId);

        foreach (var issue in validationResult.Issues)
        {
            var details = $"{issue.AttributeName}: {issue.Message}";
            if (issue.Severity == LogManagementValidationSeverity.Critical)
            {
                trustLogger.Error("LogManagementValidationCritical", "Critical", details, operationId, configurationScope: "config.json", attributeName: issue.AttributeName, pathValue: issue.Value);
            }
            else
            {
                trustLogger.Warn("LogManagementValidationInfo", "Informational", details, operationId, configurationScope: "config.json", attributeName: issue.AttributeName, pathValue: issue.Value);
            }
        }

        if (validationResult.HasCriticalIssues)
        {
            trustLogger.Error("LogManagementValidationSave", "Blocked", "Speichern wegen kritischem Loggrößenwert blockiert.", operationId);
        }
        else if (validationResult.HasInformationalIssues)
        {
            trustLogger.Warn("LogManagementValidationSave", "AllowedWithInfo", "Speichern trotz informativer Auffälligkeiten beim Loggrößenmanagement erlaubt.", operationId);
        }
        else
        {
            trustLogger.Info("LogManagementValidation", "Success", "Loggrößenvalidierung ohne Auffälligkeiten abgeschlossen.", operationId);
        }
    }

    private static void LogTimeIntervalValidationEvents(TrustLogger trustLogger, TimeIntervalValidationResult validationResult, string operationId)
    {
        trustLogger.Info("TimeIntervalValidation", "Started", "Start der Zeit-/Intervallvalidierung.", operationId);

        foreach (var issue in validationResult.Issues)
        {
            var details = $"{issue.AttributeName}: {issue.Message}";
            if (issue.Severity == TimeIntervalValidationSeverity.Critical)
            {
                trustLogger.Error("TimeIntervalValidationCritical", "Critical", details, operationId, configurationScope: issue.ConfigurationScope, attributeName: issue.AttributeName, pathValue: issue.Value);
            }
            else
            {
                trustLogger.Warn("TimeIntervalValidationHint", "Hint", details, operationId, configurationScope: issue.ConfigurationScope, attributeName: issue.AttributeName, pathValue: issue.Value);
            }
        }

        if (validationResult.HasCriticalIssues)
        {
            trustLogger.Error("TimeIntervalValidationSave", "Blocked", "Speichern wegen kritischem Zeit-/Intervallwert blockiert.", operationId);
        }
        else if (validationResult.HasHints)
        {
            trustLogger.Warn("TimeIntervalValidationSave", "AllowedWithHint", "Speichern trotz Hinweiswerten bei Zeit-/Intervallwerten erlaubt.", operationId);
        }
        else
        {
            trustLogger.Info("TimeIntervalValidation", "Success", "Zeit-/Intervallvalidierung ohne Auffälligkeiten abgeschlossen.", operationId);
        }
    }

    private static void LogPathValidationEvents(TrustLogger trustLogger, ConfigPathValidationResult validationResult, string operationId, bool isStartup)
    {
        trustLogger.Info("PathValidation", "Started", "Start der Pfadvalidierung.", operationId);

        foreach (var issue in validationResult.Issues)
        {
            var action = issue.Severity == ConfigPathValidationSeverity.Critical ? "PathValidationCritical" : "PathValidationInfo";
            var result = issue.Severity == ConfigPathValidationSeverity.Critical ? "Critical" : "Informational";
            var details = $"{issue.AttributeName}: {issue.Message}";
            if (issue.Severity == ConfigPathValidationSeverity.Critical)
            {
                trustLogger.Error(action, result, details, operationId, configurationScope: issue.ConfigurationScope, attributeName: issue.AttributeName, pathValue: issue.PathValue);
            }
            else
            {
                trustLogger.Warn(action, result, details, operationId, configurationScope: issue.ConfigurationScope, attributeName: issue.AttributeName, pathValue: issue.PathValue);
            }
        }

        if (validationResult.HasCriticalIssues)
        {
            trustLogger.Error(isStartup ? "PathValidationStartup" : "PathValidationSave", "Blocked", isStartup ? "App-Start wegen kritischem Pfadfehler abgebrochen." : "Speichern wegen kritischem Pfadfehler blockiert.", operationId);
        }
        else if (validationResult.HasInformationalIssues)
        {
            trustLogger.Warn(isStartup ? "PathValidationStartup" : "PathValidationSave", "AllowedWithInfo", isStartup ? "App-Start trotz informativer Pfadauffälligkeit erlaubt." : "Speichern trotz informativer Pfadauffälligkeit erlaubt.", operationId);
        }
        else
        {
            trustLogger.Info("PathValidation", "Success", "Pfadvalidierung ohne Auffälligkeiten abgeschlossen.", operationId);
        }
    }

    private static void LogValidationEvents(TrustLogger trustLogger, TrustedConfigValidationResult validation, string operationId)
    {
        trustLogger.Info("SchemaValidation", "Started", "Schema-Validierung gestartet.", operationId);
        if (validation.SchemaIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
        {
            trustLogger.Error("SchemaValidation", "Failed", string.Join(" | ", validation.SchemaIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else
        {
            trustLogger.Info("SchemaValidation", "Success", validation.LastSchemaValidation, operationId);
        }

        trustLogger.Info("ConsistencyValidation", "Started", "Konsistenz-Validierung gestartet.", operationId);
        if (validation.ConsistencyIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
        {
            trustLogger.Error("ConsistencyValidation", "Failed", string.Join(" | ", validation.ConsistencyIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else if (validation.ConsistencyIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Warning))
        {
            trustLogger.Warn("ConsistencyValidation", "Warnings", string.Join(" | ", validation.ConsistencyIssues.Select(issue => $"{issue.Code}: {issue.Message}")), operationId);
        }
        else
        {
            trustLogger.Info("ConsistencyValidation", "Success", validation.LastConsistencyValidation, operationId);
        }
    }

    private AppConfig BuildRuntimeConfig(UserConfigData userConfig, AppConfig validatedRuntimeConfig, string userConfigPath, string trustedConfigPath, TrustState trustState, SignatureVerificationResult trustedCatalogSignature, CatalogValidationResult catalogMatch, string startupMessage)
    {
        var config = validatedRuntimeConfig.Clone();
        config.ConfigVersion = CurrentConfigVersion;
        config.ConfigFilePath = userConfigPath;
        config.TrustedConfigFilePath = trustedConfigPath;
        config.TrustedConfigPath = trustedConfigPath;
        config.TrustLogPath = Path.Combine(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), "AppLog", "Trust.log");
        config.TrustState = trustState;
        config.LastSignatureValidation = trustState == TrustState.Trusted
            ? "TrustedConfig.cat ist gültig signiert, passt zu TrustedConfig.json und der Signer stimmt mit der EXE überein."
            : string.IsNullOrWhiteSpace(startupMessage) ? (string.IsNullOrWhiteSpace(catalogMatch.StatusMessage) ? trustedCatalogSignature.StatusMessage : catalogMatch.StatusMessage) : startupMessage;
        config.LastTrustedSignerThumbprint = trustedCatalogSignature.Thumbprint;
        config.IsSimulationModeEnforced = trustState != TrustState.Trusted;
        config.StartupSecurityBlockReason = string.Empty;
        if (config.IsSimulationModeEnforced)
        {
            config.SimulationMode = true;
        }
        return config;
    }

    private UserConfigData ToUserConfig(AppConfig config) => new()
    {
        ConfigVersion = CurrentConfigVersion,
        WindowTitle = config.WindowTitle,
        AppDataFolderName = config.AppDataFolderName,
        LocalLogDirectory = config.LocalLogDirectory,
        PsExecTimeoutSeconds = config.PsExecTimeoutSeconds,
        ConnectionStatusIntervalSeconds = config.ConnectionStatusIntervalSeconds,
        ConnectionTimeoutSeconds = config.ConnectionTimeoutSeconds,
        LiveViewRefreshSeconds = config.LiveViewRefreshSeconds,
        AutoRefreshTargetLogs = config.AutoRefreshTargetLogs,
        FallbackTaskDelayMinutes = config.FallbackTaskDelayMinutes,
        LocalProcessingDirectory = config.LocalProcessingDirectory,
        DefaultLogFiles = config.DefaultLogFiles,
        WarningKeywords = config.WarningKeywords,
        ErrorKeywords = config.ErrorKeywords,
        SuccessKeywords = config.SuccessKeywords,
        LiveConnectionStatusMessage = config.LiveConnectionStatusMessage,
        OptionsShowDefaultLogFiles = config.OptionsShowDefaultLogFiles,
        Language = config.Language,
        ShortDestinationLogs = config.ShortDestinationLogs,
        EnableAppLogRotation = config.EnableAppLogRotation,
        MaxManagedLogSizeMb = config.MaxManagedLogSizeMb,
        MaxManagedLogHistoryFiles = config.MaxManagedLogHistoryFiles,
        MaxKeptLocalLogs = config.MaxKeptLocalLogs,
        SimulationMode = config.IsSimulationModeEnforced ? true : config.SimulationMode,
        LogTabs = config.LogTabs
    };

    private TrustedConfig ToTrustedConfig(AppConfig config) => new()
    {
        ConfigVersion = CurrentConfigVersion,
        TrustedConfigPath = config.TrustedConfigPath,
        TrustLogPath = config.TrustLogPath,
        RemoteAuditLogDirectory = config.RemoteAuditLogDirectory,
        RemoteImeLogDirectory = config.RemoteImeLogDirectory,
        RemoteTempDirectory = config.RemoteTempDirectory,
        SupportClientDirectory = config.SupportClientDirectory,
        PowerShellExecutable = config.PowerShellExecutable,
        PsExecPath = config.PsExecPath,
        ToolsDirectoryPath = config.ToolsDirectoryPath,
        PsExecCatalogFilePath = config.PsExecCatalogFilePath,
        EnablePsExecCatalogValidation = config.EnablePsExecCatalogValidation,
        PsExecExpectedSigner = config.PsExecExpectedSigner,
        PsExecExpectedThumbprint = config.PsExecExpectedThumbprint,
        PsExecExpectedPublicKey = config.PsExecExpectedPublicKey,
        PsExecDownloadSource = config.PsExecDownloadSource,
        LatestPublishedPsExecVersion = config.LatestPublishedPsExecVersion,
        LocalPsExecVersion = config.LocalPsExecVersion,
        PsExecVersionStatus = config.PsExecVersionStatus,
        LastPsExecVersionCheck = config.LastPsExecVersionCheck,
        LastDownloadSource = config.LastDownloadSource,
        LastDownloadValidationResult = config.LastDownloadValidationResult,
        FallbackConfigFileName = config.FallbackConfigFileName,
        FallbackScriptFileName = config.FallbackScriptFileName,
        FallbackScheduledTaskName = config.FallbackScheduledTaskName,
        FallbackRunOnceValueName = config.FallbackRunOnceValueName,
        RemoteFallbackLogFileName = config.RemoteFallbackLogFileName,
        ConnectionFallback = config.ConnectionFallback,
        RestoreRemotingState = config.RestoreRemotingState,
        RegistryPathsForAppReset = config.RegistryPathsForAppReset,
        ImeServiceName = config.ImeServiceName,
        AllowedSources = config.AllowedSources,
        AllowedDestinations = config.AllowedDestinations
    };

    private string EnsureUserConfigForLanguage(string roamingAppData, string sourceConfigPath, UserConfigData sourceUserConfig)
    {
        var desiredDirectory = Path.Combine(roamingAppData, GetLanguageDrivenAppFolderName(sourceUserConfig.Language));
        var desiredConfigPath = Path.Combine(desiredDirectory, "config.json");

        if (File.Exists(desiredConfigPath))
        {
            MergeUserConfigIfRequired(sourceConfigPath, desiredConfigPath);
            return desiredConfigPath;
        }

        var legacyConfigPath = FindExistingUserConfigPath(roamingAppData, desiredConfigPath, sourceUserConfig);
        if (!string.IsNullOrWhiteSpace(legacyConfigPath) && File.Exists(legacyConfigPath))
        {
            Directory.CreateDirectory(desiredDirectory);
            File.Copy(legacyConfigPath, desiredConfigPath, overwrite: false);
            MergeUserConfigIfRequired(sourceConfigPath, desiredConfigPath);
            return desiredConfigPath;
        }

        Directory.CreateDirectory(desiredDirectory);
        var seededConfig = CreateLanguageAdjustedSeedConfig(sourceUserConfig);
        File.WriteAllText(desiredConfigPath, JsonSerializer.Serialize(seededConfig, _jsonOptions));
        return desiredConfigPath;
    }

    private string? FindExistingUserConfigPath(string roamingAppData, string desiredConfigPath, UserConfigData sourceUserConfig)
    {
        var candidates = new List<string>();
        AddCandidate(candidates, desiredConfigPath);
        AddCandidate(candidates, Path.Combine(roamingAppData, sourceUserConfig.AppDataFolderName ?? string.Empty, "config.json"));
        AddCandidate(candidates, Path.Combine(roamingAppData, "DAP Intune Support Suite", "config.json"));
        AddCandidate(candidates, Path.Combine(roamingAppData, "Intune Support Suite", "config.json"));

        return candidates.FirstOrDefault(path => !string.Equals(path, desiredConfigPath, StringComparison.OrdinalIgnoreCase) && File.Exists(path));
    }

    private static void AddCandidate(ICollection<string> candidates, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        if (candidates.Any(existing => string.Equals(existing, path, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        candidates.Add(path);
    }

    private UserConfigData CreateLanguageAdjustedSeedConfig(UserConfigData sourceUserConfig)
    {
        var appConfig = new AppConfig();
        ApplyUserConfig(appConfig, sourceUserConfig);
        LanguageManager.Instance.Load(AppContext.BaseDirectory, appConfig.Language, null);
        LanguageManager.Instance.ApplyLanguageDrivenConfigFields(appConfig);
        appConfig.ConfigVersion = CurrentConfigVersion;
        return ToUserConfig(appConfig);
    }

    private string GetLanguageDrivenAppFolderName(string? languageId)
    {
        LanguageManager.Instance.Load(AppContext.BaseDirectory, languageId, null);
        return LanguageManager.Instance.GetAppDisplayName();
    }

    private void EnsureProgramUserConfigExists(string sourceConfigPath)
    {
        if (File.Exists(sourceConfigPath))
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(sourceConfigPath)!);
        var defaultConfig = new UserConfigData { ConfigVersion = CurrentConfigVersion };
        File.WriteAllText(sourceConfigPath, JsonSerializer.Serialize(defaultConfig, _jsonOptions));
    }

    private void MergeUserConfigIfRequired(string sourceConfigPath, string targetConfigPath)
    {
        var sourceJson = JsonNode.Parse(File.ReadAllText(sourceConfigPath))?.AsObject() ?? new JsonObject();
        var targetJson = JsonNode.Parse(File.ReadAllText(targetConfigPath))?.AsObject() ?? new JsonObject();

        if (ParseVersion(sourceJson["ConfigVersion"]?.GetValue<string>()) <= ParseVersion(targetJson["ConfigVersion"]?.GetValue<string>()))
        {
            return;
        }

        MergeObjects(sourceJson, targetJson);
        targetJson["ConfigVersion"] = CurrentConfigVersion;
        File.WriteAllText(targetConfigPath, targetJson.ToJsonString(_jsonOptions));
    }

    private static Version ParseVersion(string? versionText)
    {
        if (string.IsNullOrWhiteSpace(versionText))
        {
            return new Version(0, 0, 0, 0);
        }

        var normalized = versionText.Trim();
        var fixedMatch = Regex.Match(normalized, @"^(?<core>\d+(?:\.\d+){0,3})(?:-fixed(?<fixed>\d*)?)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (fixedMatch.Success)
        {
            var coreParts = fixedMatch.Groups["core"].Value
                .Split('.', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => int.TryParse(part, out var value) ? value : 0)
                .ToList();

            while (coreParts.Count < 3)
            {
                coreParts.Add(0);
            }

            var revision = 0;
            if (fixedMatch.Groups["fixed"].Success)
            {
                var fixedValue = fixedMatch.Groups["fixed"].Value;
                revision = string.IsNullOrWhiteSpace(fixedValue) ? 1 : (int.TryParse(fixedValue, out var parsedRevision) ? parsedRevision : 1);
            }
            else if (coreParts.Count > 3)
            {
                revision = coreParts[3];
            }

            return new Version(coreParts[0], coreParts[1], coreParts[2], revision);
        }

        var numericParts = Regex.Matches(normalized, @"\d+")
            .Select(match => int.TryParse(match.Value, out var value) ? value : 0)
            .ToList();

        while (numericParts.Count < 4)
        {
            numericParts.Add(0);
        }

        return new Version(numericParts[0], numericParts[1], numericParts[2], numericParts[3]);
    }

    private static void MergeObjects(JsonObject source, JsonObject target)
    {
        var sourceKeys = source.Select(property => property.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var targetKeys = target.Select(property => property.Key).ToList();

        foreach (var targetKey in targetKeys.Where(existingKey => !sourceKeys.Contains(existingKey)))
        {
            target.Remove(targetKey);
        }

        foreach (var sourceProperty in source)
        {
            if (target[sourceProperty.Key] is null)
            {
                target[sourceProperty.Key] = sourceProperty.Value?.DeepClone();
                continue;
            }

            if (sourceProperty.Value is JsonObject sourceChild && target[sourceProperty.Key] is JsonObject targetChild)
            {
                MergeObjects(sourceChild, targetChild);
            }
        }
    }

    private static TrustState DetermineTrustState(SignatureVerificationResult trustedCatalogSignature, CatalogValidationResult catalogMatch, bool sameSigner, TrustedConfigValidationResult validation, bool aclValid)
    {
        if (validation.HasErrors)
        {
            return TrustState.Broken;
        }

        if (!aclValid || !trustedCatalogSignature.Success || !catalogMatch.Success || !sameSigner)
        {
            return TrustState.NotTrusted;
        }

        return TrustState.Trusted;
    }

    private static bool CheckTrustedDirectoryAcl(string trustedDirectory)
    {
        try
        {
            var security = new DirectoryInfo(trustedDirectory).GetAccessControl();
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            var adminOk = rules.Any(rule => rule.IdentityReference == admins && rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights.HasFlag(FileSystemRights.FullControl));
            var systemOk = rules.Any(rule => rule.IdentityReference == system && rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights.HasFlag(FileSystemRights.FullControl));
            return adminOk && systemOk;
        }
        catch
        {
            return false;
        }
    }

    private static void BackupUntrustedTrustedConfig(string trustedConfigPath, TrustLogger trustLogger, string operationId)
    {
        try
        {
            var trustedDirectory = Path.GetDirectoryName(trustedConfigPath)!;
            var programDirectory = Directory.GetParent(trustedDirectory)?.FullName;
            if (string.IsNullOrWhiteSpace(programDirectory))
            {
                throw new InvalidOperationException("Programmverzeichnis konnte für das NotTrusted-Backup nicht ermittelt werden.");
            }

            var notTrustedDirectory = Path.Combine(programDirectory, "NotTrusted");
            Directory.CreateDirectory(notTrustedDirectory);
            var backupPath = Path.Combine(notTrustedDirectory, "TrustedConfig.invalid.json");
            File.Copy(trustedConfigPath, backupPath, overwrite: true);
            trustLogger.Warn("TrustedConfigBackup", "Success", $"TrustedConfig nach {backupPath} gesichert.", operationId);
        }
        catch (Exception ex)
        {
            trustLogger.Error("TrustedConfigBackup", "Failed", ex.Message, operationId);
        }
    }

    private static TrustedConfig CreateDefaultTrustedConfig(string trustedConfigPath, string trustLogPath) => new()
    {
        TrustedConfigPath = trustedConfigPath,
        TrustLogPath = trustLogPath
    };

    private static ConfigurationBootstrapResult CreateFatalResult(UserConfigData userConfig, string userConfigPath, string trustedConfigPath, string trustLogPath, string message)
    {
        var defaultTrusted = CreateDefaultTrustedConfig(trustedConfigPath, trustLogPath);
        var runtimeConfig = new AppConfig
        {
            ConfigVersion = CurrentConfigVersion,
            WindowTitle = userConfig.WindowTitle,
            ConfigFilePath = userConfigPath,
            TrustedConfigFilePath = trustedConfigPath,
            TrustedConfigPath = trustedConfigPath,
            TrustLogPath = trustLogPath,
            TrustState = TrustState.Broken,
            LastSignatureValidation = message,
            LastSchemaValidation = "Nicht geprüft",
            LastConsistencyValidation = "Nicht geprüft",
            ValidationSummary = message,
            SimulationMode = true,
            IsSimulationModeEnforced = true,
            StartupSecurityBlockReason = message
        };

        return new ConfigurationBootstrapResult
        {
            Config = runtimeConfig,
            UserConfig = userConfig,
            TrustedConfig = defaultTrusted,
            UserConfigPath = userConfigPath,
            TrustedConfigPath = trustedConfigPath,
            TrustState = TrustState.Broken,
            StartupMessage = message,
            ExitApplication = true
        };
    }


    private sealed class RuntimeTrustCacheEntry
    {
        public string CacheKey { get; init; } = string.Empty;
        public AppConfig CachedConfig { get; init; } = new();
        public RuntimeTrustCheckResult Result { get; init; } = new();
    }
}
