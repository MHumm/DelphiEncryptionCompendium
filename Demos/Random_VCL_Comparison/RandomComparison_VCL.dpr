program RandomComparison_VCL;

uses
  Vcl.Forms,
  MainForm in 'MainForm.pas' {RandomCompareForm};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TRandomCompareForm, RandomCompareForm);
  Application.Run;
end.
