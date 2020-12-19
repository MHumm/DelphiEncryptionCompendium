unit MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.StdCtrls, DECUtil;

type
  TForm1 = class(TForm, IDECProgress)
    Button1: TButton;
    Edit1: TEdit;
    ProgressBar1: TProgressBar;
    procedure Button1Click(Sender: TObject);
  private
  public
    procedure OnProgress(const Min, Max, Pos: Int64); stdcall;
  end;

var
  Form1: TForm1;

implementation

uses
  System.UITypes, DECCiphers, DECCipherBase;

{$R *.dfm}

resourcestring
  rFileNameEmptyFailure = 'No input file specified!';

procedure TForm1.Button1Click(Sender: TObject);
var
  Cipher     : TCipher_AES;
  TargetFile : string;
begin
  if Edit1.Text = '' then
  begin
    MessageDlg(rFileNameEmptyFailure, mtError, [mbOK], -1);
    exit;
  end;

  Cipher := TCipher_AES.Create;

  try
    try
      // Init encryption
      Cipher.Init('Passwort', #1#2#3#4#5#6#7#99, 0);
      Cipher.Mode := cmCBCx;

      // replace file extension of input file
      TargetFile := Edit1.Text;
      Delete(TargetFile, pos('.', TargetFile), length(TargetFile));
      TargetFile := TargetFile + '.enc';

      Cipher.EncodeFile(Edit1.Text, TargetFile, self);
    except
      on E: Exception do
        MessageDlg(E.Message, mtError, [mbOK], -1);
    end;
  finally
    Cipher.Free;
  end;
end;

procedure TForm1.OnProgress(const Min, Max, Pos: Int64);
begin
  ProgressBar1.Min := Min;
  ProgressBar1.Max := Max;
  ProgressBar1.Position := Pos;
end;

end.
