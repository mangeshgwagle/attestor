@{
    RootModule        = 'Attestor.psm1'
    ModuleVersion     = '4.2.0'
    GUID              = 'a7e2b3c4-0d15-4f6a-9b8c-2e1f3a4b5c6d'
    Author            = 'Attestor'
    Description       = 'PowerShell developer CLI for the Attestor offline code-security analyzer. A thin, safety-preserving layer over the verified Python core.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-Attestor', 'Get-AttestorConfig', 'Set-AttestorConfig', 'Test-Attestor', 'Install-Attestor', 'Show-AttestorHelp')
    AliasesToExport   = @('attestor')
    CmdletsToExport   = @()
    VariablesToExport = @()
    PrivateData       = @{ PSData = @{ Tags = @('security', 'sast', 'static-analysis', 'offline') } }
}
