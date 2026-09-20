program CipherBlockModesVCL;

uses
  Vcl.Forms,
  MainFormCipherBlockmodesVCL in 'MainFormCipherBlockmodesVCL.pas' {FormMain},
  DECCipherBase in '..\..\Source\DECCipherBase.pas',
  DECBaseClass in '..\..\Source\DECBaseClass.pas',
  DECFormatBase in '..\..\Source\DECFormatBase.pas',
  DECTypes in '..\..\Source\DECTypes.pas',
  DECCRC in '..\..\Source\DECCRC.pas',
  DECUtil in '..\..\Source\DECUtil.pas',
  DECUtilRawByteStringHelper in '..\..\Source\DECUtilRawByteStringHelper.pas',
  DECCipherInterface in '..\..\Source\DECCipherInterface.pas',
  DECCipherModes in '..\..\Source\DECCipherModes.pas',
  DECCipherModesCCM in '..\..\Source\DECCipherModesCCM.pas',
  DECCipherModesGCM in '..\..\Source\DECCipherModesGCM.pas',
  DECCipherPaddings in '..\..\Source\DECCipherPaddings.pas',
  DECCiphers in '..\..\Source\DECCiphers.pas',
  DECAuthenticatedCipherModesBase in '..\..\Source\DECAuthenticatedCipherModesBase.pas',
  DECCipherFormats in '..\..\Source\DECCipherFormats.pas',
  DECRandom in '..\..\Source\DECRandom.pas',
  DECHash in '..\..\Source\DECHash.pas',
  DECHashBase in '..\..\Source\DECHashBase.pas',
  DECDataHash in '..\..\Source\DECDataHash.pas',
  DECHashAuthentication in '..\..\Source\DECHashAuthentication.pas',
  DECHashBitBase in '..\..\Source\DECHashBitBase.pas',
  DECHashInterface in '..\..\Source\DECHashInterface.pas',
  DECFormat in '..\..\Source\DECFormat.pas',
  DECData in '..\..\Source\DECData.pas',
  DECDataCipher in '..\..\Source\DECDataCipher.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
