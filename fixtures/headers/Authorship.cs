// Synthetic test declaration, not Microsoft-authored source.
// Written by: Microsoft Corporation.
// Fixture: header-claim - explicit authorship in a leading source comment.
// The source-header check recognizes authorship without a copyright notice.
// Expected scenario outcome: Stop (SkipHyenas / StopMDASH).
// The constant below is incidental; the synthetic declaration is the signal,
// not proof of who actually wrote this file.
namespace SyntheticAuthorship;

public static class Authorship
{
    public const string Example = "synthetic";
}
