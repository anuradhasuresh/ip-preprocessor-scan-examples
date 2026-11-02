// Synthetic test declaration, not Microsoft-authored source.
// Copyright (c) 2026 Microsoft Corporation.
// Fixture: header-claim - conventional copyright header.
// The source-header check reads the leading comments, not the constant below.
// Expected scenario outcome: Stop (SkipHyenas / StopMDASH).
// This tests recognition of a declaration, not verified ownership.
// Prepare-ScanInputs.ps1 also copies this file to Utf16Header.cs as UTF-16.
namespace SyntheticHeader;

public static class Header
{
    public const int Example = 42;
}
