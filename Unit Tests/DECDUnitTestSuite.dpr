program DECDUnitTestSuite;

{

  Delphi DUnit Test Project
  -------------------------
  This project contains the DUnit test framework and the GUI/Console test runners.
  Add "CONSOLE_TESTRUNNER" to the conditional defines entry in the project options
  to use the console test runner.  Otherwise the GUI test runner will be used by
  default.

}

{$IFDEF CONSOLE_TESTRUNNER}
{$APPTYPE CONSOLE}
{$ENDIF}

uses
  Forms,
  TestFramework,
  GUITestRunner,
  TextTestRunner,
  TestDECUtil in 'Tests\TestDECUtil.pas',
  DECCipherBase in '..\Source\DECCipherBase.pas',
  DECBaseClass in '..\Source\DECBaseClass.pas',
  DECCRC in '..\Source\DECCRC.pas',
  DECData in '..\Source\DECData.pas',
  DECFormat in '..\Source\DECFormat.pas',
  DECFormatBase in '..\Source\DECFormatBase.pas',
  DECHash in '..\Source\DECHash.pas',
  DECRandom in '..\Source\DECRandom.pas',
  DECUtil in '..\Source\DECUtil.pas',
  TestDECFormatBase in 'Tests\TestDECFormatBase.pas',
  TestDECFormat in 'Tests\TestDECFormat.pas',
  TestDECHash in 'Tests\TestDECHash.pas',
  TestDECCRC in 'Tests\TestDECCRC.pas',
  TestDECCipher in 'Tests\TestDECCipher.pas',
  DECCiphers in '..\Source\DECCiphers.pas',
  DECHashBase in '..\Source\DECHashBase.pas',
  DECCipherFormats in '..\Source\DECCipherFormats.pas',
  DECTypes in '..\Source\DECTypes.pas',
  DECCipherModes in '..\Source\DECCipherModes.pas',
  TestDECCipherModes in 'Tests\TestDECCipherModes.pas',
  TestDECBaseClass in 'Tests\TestDECBaseClass.pas',
  DECUtilRawByteStringHelper in '..\Source\DECUtilRawByteStringHelper.pas',
  TestDECTestDataContainer in 'Tests\TestDECTestDataContainer.pas',
  DECCipherInterface in '..\Source\DECCipherInterface.pas',
  DECHashInterface in '..\Source\DECHashInterface.pas',
  TestDECCipherFormats in 'Tests\TestDECCipherFormats.pas';

{$R *.RES}

begin
  ReportMemoryLeaksOnShutdown := true;
  Application.Initialize;
  if IsConsole then
    TextTestRunner.RunRegisteredTests.Free
  else
    GUITestRunner.RunRegisteredTests;
end.

