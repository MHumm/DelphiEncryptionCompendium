{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

/// <summary>
///   Simple demonstration of using the IDECProgress interface for displaying
///   progress of an operation
/// </summary>
unit MainFormProgressVCL;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.StdCtrls, Vcl.Mask, Vcl.ExtCtrls,
  DECTypes, DECCipherBase, DECCiphers, DECFormat, DECRandom, DECUtil;

type
  TFormMain = class(TForm)
    ButtonEncrypt: TButton;
    EditEncrypt: TEdit;
    ProgressBar1: TProgressBar;
    RadioButtonMethod: TRadioButton;
    RadioButtonProcedure: TRadioButton;
    RadioButtonAnonMethod: TRadioButton;
    PageControl1: TPageControl;
    tabEncrypt: TTabSheet;
    tabDecrypt: TTabSheet;
    ButtonDecrypt: TButton;
    EditDecrypt: TEdit;
    EditKey: TLabeledEdit;
    EditIV: TLabeledEdit;
    ButtonCreateKeyAndIV: TButton;
    LabelPaddingMode: TLabel;
    ComboBoxPaddingMode: TComboBox;
    procedure ButtonEncryptClick(Sender: TObject);
    procedure ButtonDecryptClick(Sender: TObject);
    procedure ButtonCreateKeyAndIVClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    /// <summary>
    ///   Instance of the encryption/decryption class used
    /// </summary>
    FCipher: TCipher_AES;

    /// <summary>
    ///   Returns the selected padding mode
    /// </summary>
    function GetSelectedPaddingMode: TPaddingMode;

    /// <summary>
    ///   Fills the padding mode combobox with the available modes
    /// </summary>
    procedure InitPaddingModesCombo;

    /// <summary>
    ///   Progress event called by the encryption/decryption methods
    /// </summary>
    /// <param name="Size">
    ///   Size of the of the file to be processed in bytes
    /// </param>
    /// <param name="Pos">
    ///   Byte position the algorithm is currently processing
    /// </param>
    /// <param name="State">
    ///   Status of the operation: Started, Processing, Finished
    /// </param>
    procedure OnProgress(Size, Pos: Int64; State: TDECProgressState);
  end;

var
  FormMain: TFormMain;

implementation

uses
  System.UITypes,
  System.TypInfo;

{$R *.dfm}

resourcestring
  rFileNameEmptyFailure = 'No input file specified!';

procedure TFormMain.FormCreate(Sender: TObject);
begin
  FCipher      := TCipher_AES.Create;
  FCipher.Mode := cmCBCx;

  InitPaddingModesCombo;
end;

procedure TFormMain.FormDestroy(Sender: TObject);
begin
  FCipher.Free;
end;

procedure TFormMain.ButtonCreateKeyAndIVClick(Sender: TObject);
begin
  EditKey.Text := StringOf(TFormat_Base64.Encode(
                    RandomBytes(FCipher.Context.KeySize)));

  EditIV.Text := StringOf(TFormat_Base64.Encode(
                    RandomBytes(FCipher.Context.BlockSize)));
end;

procedure OnProgressProc(Size, Pos: Int64; State: TDECProgressState);
begin
  FormMain.ProgressBar1.Min := 0;
  FormMain.ProgressBar1.Max := Size;

  if (State = Finished) then
    FormMain.ProgressBar1.Position := FormMain.ProgressBar1.Max
  else
    FormMain.ProgressBar1.Position := Pos;
end;

procedure TFormMain.OnProgress(Size, Pos: Int64; State: TDECProgressState);
begin
  ProgressBar1.Min := 0;
  ProgressBar1.Max := Size;

  if (State = Finished) then
    ProgressBar1.Position := ProgressBar1.Max
  else
    ProgressBar1.Position := Pos;
end;

procedure TFormMain.ButtonEncryptClick(Sender: TObject);
var
  SourceFile, DestFile: string;
  PaddingMode: TPaddingMode;
begin
  if EditEncrypt.Text = '' then
  begin
    MessageDlg(rFileNameEmptyFailure, mtError, [mbOK], -1);
    exit;
  end;

  PaddingMode := GetSelectedPaddingMode;

  try
    // Init encryption
    FCipher.Init(
      RawStringToBytes(TFormat_Base64.Decode(RawByteString(EditKey.Text))),
      RawStringToBytes(TFormat_Base64.Decode(RawByteString(EditIV.Text))),
      0,
      PaddingMode);

    // replace file extension of input file
    SourceFile := EditEncrypt.Text;
    DestFile := ChangeFileExt(SourceFile, '.enc');

    // depending on selected radio button demo a different progress event technique
    if RadioButtonMethod.Checked then
      FCipher.EncodeFile(SourceFile, DestFile, OnProgress)
    else
      if RadioButtonProcedure.Checked then
        FCipher.EncodeFile(SourceFile, DestFile, OnProgressProc)
    else
      if RadioButtonAnonMethod.Checked then
        FCipher.EncodeFile(SourceFile, DestFile,
                           procedure(Size, Pos: Int64; State: TDECProgressState)
                           begin
                             ProgressBar1.Min := 0;
                             ProgressBar1.Max := Size;

                             if (State = Finished) then
                               ProgressBar1.Position := ProgressBar1.Max
                             else
                               ProgressBar1.Position := Pos;
                           end);
  except
    on E: Exception do
      MessageDlg(E.Message, mtError, [mbOK], -1);
  end;
end;

procedure TFormMain.ButtonDecryptClick(Sender: TObject);
var
  SourceFile, DestFile: string;
  PaddingMode: TPaddingMode;
begin
  if EditDecrypt.Text = '' then
  begin
    MessageDlg(rFileNameEmptyFailure, mtError, [mbOK], -1);
    exit;
  end;

  PaddingMode := GetSelectedPaddingMode;

  try
    // Init encryption
    FCipher.Init(RawStringToBytes(TFormat_Base64.Decode(RawByteString(EditKey.Text))),
                 RawStringToBytes(TFormat_Base64.Decode(RawByteString(EditIV.Text))),
                 0,
                 PaddingMode);

    // replace file extension of input file
    SourceFile := EditDecrypt.Text;
    DestFile := ChangeFileExt(SourceFile, '.dec.txt');

    // depending on selected radio button demo a different progress event technique
    if RadioButtonMethod.Checked then
      FCipher.DecodeFile(SourceFile, DestFile, OnProgress)
    else
      if RadioButtonProcedure.Checked then
        FCipher.DecodeFile(SourceFile, DestFile, OnProgressProc)
      else
        if RadioButtonAnonMethod.Checked then
          FCipher.DecodeFile(SourceFile, DestFile,
                             procedure(Size, Pos: Int64; State: TDECProgressState)
                             begin
                               ProgressBar1.Min := 0;
                               ProgressBar1.Max := Size;

                               if (State = Finished) then
                                 ProgressBar1.Position := ProgressBar1.Max
                               else
                                 ProgressBar1.Position := Pos;
                             end);
  except
    on E: Exception do
      MessageDlg(E.Message, mtError, [mbOK], -1);
  end;
end;

function TFormMain.GetSelectedPaddingMode: TPaddingMode;
var
  ModeStr : string;
begin
  ModeStr := ComboBoxPaddingMode.Items[ComboBoxPaddingMode.ItemIndex];
  // Determine selected block chaining method via RTTI (runtime type information)
  Result := TPaddingMode(System.TypInfo.GetEnumValue(TypeInfo(TPaddingMode),
                                                     ModeStr));
end;

procedure TFormMain.InitPaddingModesCombo;
var
  PaddingMode: TPaddingMode;
begin
  ComboBoxPaddingMode.Clear;

  for PaddingMode := low(TPaddingMode) to high(TPaddingMode) do
    ComboBoxPaddingMode.Items.Add(System.TypInfo.GetEnumName(TypeInfo(TPaddingMode),
                                                             Integer(PaddingMode)));

  ComboBoxPaddingMode.ItemIndex := 0;
end;

end.
