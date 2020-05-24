program Cipher_FMX;

uses
  System.StartUpCopy,
  FMX.Forms,
  MainForm in 'MainForm.pas' {FormMain},
  DECBaseClass in '..\..\Source\DECBaseClass.pas',
  DECFormat in '..\..\Source\DECFormat.pas',
  DECFormatBase in '..\..\Source\DECFormatBase.pas',
  DECUtil in '..\..\Source\DECUtil.pas',
  DECTypes in '..\..\Source\DECTypes.pas',
  DECCRC in '..\..\Source\DECCRC.pas',
  DECCipherBase in '..\..\Source\DECCipherBase.pas',
  DECCipherModes in '..\..\Source\DECCipherModes.pas',
  DECCiphers in '..\..\Source\DECCiphers.pas',
  DECData in '..\..\Source\DECData.pas',
  DECCipherFormats in '..\..\Source\DECCipherFormats.pas',
  DECUtilRawByteStringHelper in '..\..\Source\DECUtilRawByteStringHelper.pas',
  DECCipherInterface in '..\..\Source\DECCipherInterface.pas',
  DECDataCipher in '..\..\Source\DECDataCipher.pas';

{$R *.res}

begin
  Application.Initialize;
  // TMainForm
  Application.CreateForm(TMainForm, FormMain);
  Application.Run;
end.
