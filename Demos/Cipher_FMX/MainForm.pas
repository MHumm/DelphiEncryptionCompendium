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

unit MainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.Layouts,
  FMX.StdCtrls, FMX.ListBox, FMX.Controls.Presentation, FMX.Edit, System.Rtti,
  FMX.Grid, FMX.ScrollBox, FMX.ComboEdit,
  {$IF RTLVersion < 31}
  {$ELSE}
  FMX.Grid.Style,
  {$ENDIF}
  DECCipherBase, DECFormatBase, DECCipherModes;

type
  /// <summary>
  ///   Form of the cross platform FMX Cipher demo
  /// </summary>
  TFormMain = class(TForm)
    VertScrollBox1: TVertScrollBox;
    LayoutTop: TLayout;
    Label2: TLabel;
    ComboBoxCipherAlgorithm: TComboBox;
    Label5: TLabel;
    ComboBoxInputFormatting: TComboBox;
    Label6: TLabel;
    ComboBoxOutputFormatting: TComboBox;
    Label1: TLabel;
    EditKey: TEdit;
    Label3: TLabel;
    EditInitVector: TEdit;
    Label4: TLabel;
    EditFiller: TEdit;
    Label7: TLabel;
    ComboBoxChainingMethod: TComboBox;
    CheckBoxLiveCalc: TCheckBox;
    Label8: TLabel;
    StringGridContext: TStringGrid;
    StringColumn1: TStringColumn;
    StringColumn2: TStringColumn;
    Label9: TLabel;
    Label10: TLabel;
    EditPlainText: TEdit;
    EditCipherText: TEdit;
    ButtonEncrypt: TButton;
    ButtonDecrypt: TButton;
    LayoutEncrypt: TLayout;
    LabelVersion: TLabel;
    LayoutAuthentication: TLayout;
    Label11: TLabel;
    EditAuthenticatedData: TEdit;
    Label12: TLabel;
    EditExpectedAuthenthicationResult: TEdit;
    Label13: TLabel;
    Label14: TLabel;
    EditCalculatedAuthehticationValue: TEdit;
    ComboEditLengthCalculatedValue: TComboEdit;
    procedure FormResize(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure ComboBoxCipherAlgorithmChange(Sender: TObject);
    procedure ButtonEncryptClick(Sender: TObject);
    procedure EditPlainTextChangeTracking(Sender: TObject);
    procedure ButtonDecryptClick(Sender: TObject);
    procedure ComboBoxChainingMethodChange(Sender: TObject);
  private
    /// <summary>
    ///   Add all registered formats to the combobox and select TFormat_Copy
    ///   if available
    /// </summary>
    procedure InitFormatCombos;
    /// <summary>
    ///   Add all registered ciphers except TCipher_Null to the combobox
    /// </summary>
    procedure InitCipherCombo;
    /// <summary>
    ///   Add all defined cipher block chaining modes to the combo box
    /// </summary>
    procedure InitCipherModes;
    /// <summary>
    ///   Displays an error message in a platform independent way
    /// </summary>
    /// <param name="ErrorMsg">
    ///   Message to display
    /// </param>
    procedure ShowErrorMessage(ErrorMsg: string);
    /// <summary>
    ///   Returns the selected block chaining mode
    /// </summary>
    function GetSelectedCipherMode: TCipherMode;
    /// <summary>
    ///   Get the settings for the input and output formatting and checks whether
    ///   the user has entered any key, input vector and filler byte values.
    /// </summary>
    /// <param name="InputFormatting">
    ///   An instance of the input format class selected will be returned here
    /// </param>
    /// <param name="OutputFormatting">
    ///   An instance of the output format class selected will be returned here
    /// </param>
    /// <returns>
    ///   true if input and output instances could be created and the user has
    ///   entered values for key, input vector and filler byte. False if one of
    ///   the conditions was not met.
    /// </returns>
    function GetSettings(var InputFormatting  : TDECFormatClass;
                         var OutputFormatting : TDECFormatClass): Boolean;
    /// <summary>
    ///   Set all authehtication related properties of the cipher isntance to
    ///   the values the user entered
    /// </summary>
    procedure SetAuthenticationParams(Cipher : TDECCipherModes);
    /// <summary>
    ///   Creates an instance of the selected cipher algorithm and initializes it.
    ///   It is expected that all selectable (means all registered) algorithms
    ///   inherit from TDECCipherModes at least.
    /// </summary>
    /// <param name="Cipher">
    ///   The created instance.
    /// </param>
    /// <returns>
    ///   true if the entered initialization vector and filler were properly
    ///   hex formatted so the instance could properly created and initialized
    ///   with the key, initialization vector and filler.
    /// </returns>
    function GetCipherAlgorithm(var Cipher: TDECCipherModes): Boolean;
    /// <summary>
    ///   Checks whether the selected cipher block chaining mode is an
    ///   authenticated one (requires selection of a compatible cipher algorithm
    ///   prior to that) and displays the result in the cipher properties grid.
    /// </summary>
    procedure UpdateIsAuthenticated;
    /// <summary>
    ///   If an authehticated cipher mode is selected the layout with the
    ///   parameters for that one is made visible and the encryption/decryption
    ///    layout is placed below it.
    /// </summary>
    procedure UpdateLayoutPositions;
  public
  end;

var
  FormMain: TFormMain;

implementation

uses
  System.TypInfo, Generics.Collections, FMX.Platform,
  DECBaseClass, DECFormat,
  DECCipherFormats, DECCiphers, DECUtil, DECCipherInterface
  {$IFDEF Android}
  ,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.Helpers,
  Androidapi.JNI.App
  {$ENDIF};

{$R *.fmx}

procedure TFormMain.ButtonDecryptClick(Sender: TObject);
var
  Cipher           : TDECCipherModes;
  InputFormatting  : TDECFormatClass;
  OutputFormatting : TDECFormatClass;
  InputBuffer      : TBytes;
  OutputBuffer     : TBytes;
begin
  if not GetSettings(InputFormatting, OutputFormatting) then
    exit;

  if ComboBoxCipherAlgorithm.ItemIndex >= 0 then
  begin
    if not GetCipherAlgorithm(Cipher) then
      exit;

    try
      InputBuffer  := System.SysUtils.BytesOf(EditCipherText.Text);

      if InputFormatting.IsValid(InputBuffer) then
      begin
        // Set all authentication related properties
        SetAuthenticationParams(Cipher);

        try
          OutputBuffer := (Cipher as TDECFormattedCipher).DecodeBytes(OutputFormatting.Decode(InputBuffer));
          // in case of an authenticated cipher mode like cmGCM the Done method
          // will raise an exceptino when the calculated authentication value does
          // not match the given expected one
          (Cipher as TDECFormattedCipher).Done;
        except
          On e:Exception do
            ShowErrorMessage('Failure in decryption:' + sLineBreak + e.Message);
        end;

        if Cipher.IsAuthenticated then
          EditCalculatedAuthehticationValue.Text :=
            StringOf(TFormat_HEXL.Encode(Cipher.CalculatedAuthenticationResult));

        EditPlainText.Text := string(DECUtil.BytesToRawString(InputFormatting.Encode(OutputBuffer)));
      end
      else
        ShowErrorMessage('Input has wrong format');
    finally
      Cipher.Free;
    end;
  end
  else
    ShowErrorMessage('No cipher algorithm selected');
end;

procedure TFormMain.ButtonEncryptClick(Sender: TObject);
var
  Cipher           : TDECCipherModes;
  InputFormatting  : TDECFormatClass;
  OutputFormatting : TDECFormatClass;
  InputBuffer      : TBytes;
  OutputBuffer     : TBytes;
begin
  if not GetSettings(InputFormatting, OutputFormatting) then
    exit;

  if ComboBoxCipherAlgorithm.ItemIndex >= 0 then
  begin
    if not GetCipherAlgorithm(Cipher) then
      exit;

    try
      InputBuffer  := System.SysUtils.BytesOf(EditPlainText.Text);

      if InputFormatting.IsValid(InputBuffer) then
      begin
        // Set all authentication related properties
        SetAuthenticationParams(Cipher);

        try
          OutputBuffer := (Cipher as TDECFormattedCipher).EncodeBytes(InputFormatting.Decode(InputBuffer));
          (Cipher as TDECFormattedCipher).Done;
        except
          On e:Exception do
            ShowErrorMessage('Failure in encryption:' + sLineBreak + e.Message);
        end;

        EditCipherText.Text := string(DECUtil.BytesToRawString(OutputFormatting.Encode(OutputBuffer)));

        if Cipher.IsAuthenticated then
          EditCalculatedAuthehticationValue.Text :=
            StringOf(TFormat_HEXL.Encode(Cipher.CalculatedAuthenticationResult));
      end
      else
        ShowErrorMessage('Input has wrong format');
    finally
      Cipher.Free;
    end;
  end
  else
    ShowErrorMessage('No cipher algorithm selected');
end;

procedure TFormMain.SetAuthenticationParams(Cipher : TDECCipherModes);
begin
  Assert(Assigned(Cipher));

  // Set all authentication related properties
  if Cipher.IsAuthenticated then
  begin
    Cipher.AuthenticationResultBitLength :=
      ComboEditLengthCalculatedValue.Text.ToInteger;

    Cipher.DataToAuthenticate :=
      TFormat_HexL.Decode(BytesOf(RawByteString(EditAuthenticatedData.Text)));

    Cipher.ExpectedAuthenticationResult :=
      TFormat_HexL.Decode(BytesOf(RawByteString(EditExpectedAuthenthicationResult.Text)));
  end;
end;

function TFormMain.GetSettings(var InputFormatting  : TDECFormatClass;
                               var OutputFormatting : TDECFormatClass): Boolean;
begin
  result := false;

  if ComboBoxInputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    InputFormatting := TDECFormat.ClassByName(
      ComboBoxInputFormatting.Items[ComboBoxInputFormatting.ItemIndex]);
  end
  else
  begin
    ShowErrorMessage('No input format selected');
    exit;
  end;

  if ComboBoxOutputFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    OutputFormatting := TDECFormat.ClassByName(
      ComboBoxOutputFormatting.Items[ComboBoxOutputFormatting.ItemIndex]);
  end
  else
  begin
    ShowErrorMessage('No output format selected');
    exit;
  end;

  if EditKey.Text.IsEmpty or EditInitVector.Text.IsEmpty or EditFiller.Text.IsEmpty then
  begin
    ShowErrorMessage('No key, initialization vector or filler byte given');
    exit;
  end;

  result := true;
end;

function TFormMain.GetCipherAlgorithm(var Cipher : TDECCipherModes):Boolean;
begin
  result := false;

  // Find the class type of the selected cipher class and create an instance of it
  Cipher := TDECCipher.ClassByName(
    ComboBoxCipherAlgorithm.Items[ComboBoxCipherAlgorithm.ItemIndex]).Create as TDECCipherModes;

  if TFormat_HEXL.IsValid(RawByteString(EditInitVector.Text)) and
     TFormat_HEXL.IsValid(RawByteString(EditFiller.Text)) then
  begin
    Cipher.Mode := GetSelectedCipherMode;

    Cipher.Init(BytesOf(TFormat_HexL.Decode(RawByteString(EditKey.Text))),
                BytesOf(TFormat_HexL.Decode(RawByteString(EditInitVector.Text))),
                StrToInt('0x' + EditFiller.Text));
  end
  else
  begin
    ShowErrorMessage('Init vector or filler byte  not given in hexadecimal representation');
    exit;
  end;

  result := true;
end;

function TFormMain.GetSelectedCipherMode:TCipherMode;
var
  ModeStr : string;
begin
  ModeStr := ComboBoxChainingMethod.Items[ComboBoxChainingMethod.ItemIndex];

  if ModeStr.Contains('(') then
    ModeStr := ModeStr.Remove(ModeStr.IndexOf('(')-1);

  // Determine selected block chaining method via RTTI (runtime type information)
  result := TCipherMode(System.TypInfo.GetEnumValue(
              TypeInfo(TCipherMode),
              ModeStr));
end;

procedure TFormMain.ShowErrorMessage(ErrorMsg: string);
{$IF RTLVersion > 30}
var
  AsyncDlg : IFMXDialogServiceASync;
{$ENDIF}
begin
  {$IF RTLVersion > 30}
  if TPlatformServices.Current.SupportsPlatformService(IFMXDialogServiceAsync,
                                                       IInterface(AsyncDlg)) then
    AsyncDlg.MessageDialogAsync(Translate(ErrorMsg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], TMsgDlgBtn.mbOk, 0,
    procedure (const AResult: TModalResult)
    begin
    end);
  {$ELSE}
  MessageDlg(Translate(ErrorMsg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], 0);
  {$ENDIF}
end;

procedure TFormMain.ComboBoxChainingMethodChange(Sender: TObject);
begin
  UpdateIsAuthenticated;
end;

procedure TFormMain.UpdateIsAuthenticated;
var
  Cipher : TDECCipherModes;
begin
  if (not EditInitVector.Text.IsEmpty) and (not EditFiller.Text.IsEmpty) then
  begin
    try
      if GetCipherAlgorithm(Cipher) then
      begin
        try
          if Cipher.IsAuthenticated then
          begin
            StringGridContext.Cells[1, 7] := 'yes';
            LayoutAuthentication.Visible := true;
            UpdateLayoutPositions;
          end
          else
          begin
            StringGridContext.Cells[1, 7] := 'no';
            LayoutAuthentication.Visible := false;
            UpdateLayoutPositions;
          end;
        finally
          Cipher.Free;
        end;
      end
      else
      begin
        StringGridContext.Cells[1, 7] := 'no';
        LayoutAuthentication.Visible := false;
        UpdateLayoutPositions;
      end;
    except
      ShowErrorMessage('Invalid cipher algorithm selected for selected block '+
                       'chaining mode');

      StringGridContext.Cells[1, 7] := 'no';
      LayoutAuthentication.Visible := false;
      UpdateLayoutPositions;
    end;
  end
  else
  begin
    StringGridContext.Cells[1, 7] := 'no';
    LayoutAuthentication.Visible := false;
    UpdateLayoutPositions;
  end;
end;

procedure TFormMain.UpdateLayoutPositions;
begin
  if LayoutAuthentication.Visible then
    LayoutEncrypt.Position.Y := LayoutTop.Height + LayoutAuthentication.Height
  else
    LayoutEncrypt.Position.Y := LayoutTop.Height;
end;

procedure TFormMain.ComboBoxCipherAlgorithmChange(Sender: TObject);
var
  Context : TCipherContext;
begin
  Context := TDECCipher.ClassByName(
    ComboBoxCipherAlgorithm.Items[ComboBoxCipherAlgorithm.ItemIndex]).Context;

  StringGridContext.RowCount := 8;
  StringGridContext.Cells[0, 0] := 'Key size (bit)';
  StringGridContext.Cells[0, 1] := 'Block size (bit)';
  StringGridContext.Cells[0, 2] := 'Buffer size (bit)';
  StringGridContext.Cells[0, 3] := 'User size (bit)';
  StringGridContext.Cells[0, 4] := 'User save';
  StringGridContext.Cells[0, 5] := 'Cipher mode';
  StringGridContext.Cells[0, 6] := 'Cipher key';
  StringGridContext.Cells[0, 7] := 'Authenticated';

  StringGridContext.Cells[1, 0] :=  IntToStr(Context.KeySize*8);
  StringGridContext.Cells[1, 1] :=  IntToStr(Context.BlockSize*8);
  StringGridContext.Cells[1, 2] :=  IntToStr(Context.BufferSize*8);
  StringGridContext.Cells[1, 3] :=  IntToStr(Context.AdditionalBufferSize*8);
  StringGridContext.Cells[1, 4] :=  BoolToStr(Context.NeedsAdditionalBufferBackup, true);

  if ctBlock in Context.CipherType then
    StringGridContext.Cells[1, 5] := 'block cipher'
  else
    StringGridContext.Cells[1, 5] := 'stream cipher';

  if ctSymmetric in Context.CipherType then
    StringGridContext.Cells[1, 6] := 'symmetric'
  else
    StringGridContext.Cells[1, 6] := 'asymmetric';

  UpdateIsAuthenticated;
end;

procedure TFormMain.EditPlainTextChangeTracking(Sender: TObject);
begin
  if CheckBoxLiveCalc.IsChecked then
    ButtonEncryptClick(self)
end;

procedure TFormMain.FormCreate(Sender: TObject);
var
  AppService : IFMXApplicationService;
begin
  if TPlatformServices.Current.SupportsPlatformService(IFMXApplicationService,
                                                       IInterface(AppService)) then
    LabelVersion.Text := format(LabelVersion.Text, [AppService.AppVersion])
  else
    LabelVersion.Text := format(LabelVersion.Text, ['']);

  InitFormatCombos;
  InitCipherCombo;
  InitCipherModes;
end;

procedure TFormMain.FormResize(Sender: TObject);
begin
  LayoutTop.Width    := VertScrollBox1.Width;
end;

procedure TFormMain.InitFormatCombos;
var
  MyClass : TPair<Int64, TDECClass>;
  Formats : TStringList;
  CopyIdx : Integer;
begin
  Formats := TStringList.Create;

  try
    for MyClass in TDECFormat.ClassList do
      Formats.Add(MyClass.Value.ClassName);

    Formats.Sort;
    ComboBoxInputFormatting.Items.AddStrings(Formats);
    ComboBoxOutputFormatting.Items.AddStrings(Formats);

    if Formats.Count > 0 then
    begin
      if Formats.Find('TFormat_Copy', CopyIdx) then
      begin
        ComboBoxInputFormatting.ItemIndex  := CopyIdx;
        ComboBoxOutputFormatting.ItemIndex := CopyIdx;
      end
      else
      begin
        ComboBoxInputFormatting.ItemIndex  := 0;
        ComboBoxOutputFormatting.ItemIndex := 0;
      end;
    end;
  finally
    Formats.Free;
  end;
end;

procedure TFormMain.InitCipherCombo;
var
  MyClass : TPair<Int64, TDECClass>;
  Ciphers : TStringList;
begin
  Ciphers := TStringList.Create;

  try
    // Alternatively you can use TDECCipher.ClassList.GetClassList(Ciphers); but
    // then it's harder to remove TCipher_Null from the list
    for MyClass in TDECCipher.ClassList do
    begin
      if (MyClass.Value <> TCipher_Null) then
        Ciphers.Add(MyClass.Value.ClassName);
    end;

    Ciphers.Sort;
    ComboBoxCipherAlgorithm.Items.AddStrings(Ciphers);

    if Ciphers.Count > 0 then
      ComboBoxCipherAlgorithm.ItemIndex  := 0;
  finally
    Ciphers.Free;
  end;
end;

procedure TFormMain.InitCipherModes;
var
  Mode : TCipherMode;
  Name : string;
begin
  for Mode := low(TCipherMode) to high(TCipherMode) do
  begin
    Name := System.TypInfo.GetEnumName(TypeInfo(TCipherMode), Integer(Mode));

    if IsAuthenticatedBlockMode(Mode) then
      name := name + ' (authenticated)';

    ComboBoxChainingMethod.Items.Add(Name);
  end;

  if ComboBoxChainingMethod.Items.Count > 0 then
    ComboBoxChainingMethod.ItemIndex := 0;
end;

end.
