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

unit MainFormCipherFMX;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.Layouts,
  FMX.ListBox, FMX.Controls.Presentation, FMX.StdCtrls, System.Rtti,
  FMX.Grid, FMX.ScrollBox, FMX.ComboEdit, FMX.Edit, FMX.Platform,
  {$IF RTLVersion < 31}
  {$ELSE}
  FMX.Grid.Style,
  {$ENDIF}
  DECCipherBase, DECFormatBase, DECCipherModes;

type
  /// <summary>
  ///   Used for lists of cipher block chaining modes
  /// </summary>
  TCipherModes = set of TCipherMode;

  /// <summary>
  ///   Form of the cross platform FMX Cipher demo
  /// </summary>
  TFormMain = class(TForm)
    LayoutAuthentication: TLayout;
    Label11: TLabel;
    EditAuthenticatedData: TEdit;
    Label12: TLabel;
    EditExpectedAuthenthicationResult: TEdit;
    Label13: TLabel;
    Label14: TLabel;
    EditCalculatedAuthenticationValue: TEdit;
    ComboEditLengthCalculatedValue: TComboEdit;
    VertScrollBox1: TVertScrollBox;
    LayoutTop: TLayout;
    Label2: TLabel;
    ComboBoxCipherAlgorithm: TComboBox;
    Label7: TLabel;
    ComboBoxChainingMethod: TComboBox;
    Label8: TLabel;
    StringGridContext: TStringGrid;
    StringColumn1: TStringColumn;
    StringColumn2: TStringColumn;
    LayoutCipherSettings: TLayout;
    Label1: TLabel;
    EditKey: TEdit;
    Label3: TLabel;
    EditInitVector: TEdit;
    LabelFillerByte: TLabel;
    EditFiller: TEdit;
    LayoutEncrypt: TLayout;
    ButtonDecrypt: TButton;
    ButtonEncrypt: TButton;
    EditCipherText: TEdit;
    EditPlainText: TEdit;
    Label10: TLabel;
    Label9: TLabel;
    LabelVersion: TLabel;
    Label5: TLabel;
    ComboBoxPlainTextFormatting: TComboBox;
    Label6: TLabel;
    ComboBoxCipherTextFormatting: TComboBox;
    procedure FormCreate(Sender: TObject);
    procedure ComboBoxCipherAlgorithmChange(Sender: TObject);
    procedure ComboBoxChainingMethodChange(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure ButtonEncryptClick(Sender: TObject);
    procedure ButtonDecryptClick(Sender: TObject);
    procedure ButtonCopyClick(Sender: TObject);
    procedure FormResize(Sender: TObject);
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
    ///   Displays a message in a platform independent way
    /// </summary>
    /// <param name="Msg">
    ///   Message to display
    /// </param>
    /// <param name="MessageType">
    ///   Type of the message: mtError...
    /// </param>
    procedure ShowMessage(Msg: string; MessageType:TMsgDlgType);
    /// <summary>
    ///   Set all authehtication related properties of the cipher isntance to
    ///   the values the user entered
    /// </summary>
    procedure SetAuthenticationParams(Cipher : TDECCipherModes);

    /// <summary>
    ///   Makes the authentication fields visible or not and adjusts the layout
    ///   accordingly.
    /// </summary>
    /// <param name="Visible">
    ///   True when the authentication fields shall be visible
    /// </param>
    procedure SetAuthenticationFieldsVisibility(Visible: Boolean);
    /// <summary>
    ///   Checks whether the currently selected combination of cipher algorithm
    ///   and cipher mode is an authenticated one.
    /// </summary>
    function IsAuthenticatedCipher: Boolean;
    /// <summary>
    ///   Creates and instance of the selected cipher and already sets its
    ///   block chaining mode, as that's a combo box which always has a selected
    ///   value.
    /// </summary>
    /// <returns>
    ///   Created instance of the selected cipher but Init has not been called yet.
    /// </returns>
    function GetCipherInstance: TDECCipherModes;
    /// <summary>
    ///   Creates and instance of the selected cipher, sets its block chaining
    ///   mode and call init with the entered key, initialization vector and
    ///   filler byte values.
    /// </summary>
    /// <returns>
    ///   Created instance of the selected cipher but Init has not been called yet.
    /// </returns>
    function GetInitializedCipherInstance: TDECCipherModes;
    /// <summary>
    ///   Returns the selected block chaining mode
    /// </summary>
    function GetSelectedCipherMode: TCipherMode;
    /// <summary>
    ///   If a cipher and block chaining mode is selected which provide
    ///   authentication capabilities show the authentication fields. Also show
    ///   authentication status info in the grid.
    /// </summary>
    procedure UpdateAuthenticationStatus;
    /// <summary>
    ///   Get the settings for the input and output formatting and checks whether
    ///   the user has entered any key, input vector and filler byte values.
    /// </summary>
    /// <param name="PlainTextFormatting">
    ///   An instance of the input format class selected will be returned here
    /// </param>
    /// <param name="CipherTextFormatting">
    ///   An instance of the output format class selected will be returned here
    /// </param>
    /// <returns>
    ///   true if input and output instances could be created and the user has
    ///   entered values for key, input vector and filler byte. False if one of
    ///   the conditions was not met.
    /// </returns>
    function GetFormatSettings(var PlainTextFormatting  : TDECFormatClass;
                               var CipherTextFormatting : TDECFormatClass): Boolean;

    /// <summary>
    ///   Get the clipboard instance to be able to put something in it
    /// </summary>
    /// <param name="Clipboard">
    ///   If successfull the aquired clipboard object
    /// </param>
    /// <returns>
    ///   true if the clipboard instance could be aquired
    /// </returns>
    function TryGetClipboardService(out Clipboard: IFMXClipboardService): Boolean;
    /// <summary>
    ///   Puts a sting into the clipboard
    /// </summary>
    /// <param name="s">
    ///   String to put into the clipboard
    /// </param>
    procedure StringToClipboard(const s: string);
    /// <summary>
    ///   Returns the list of block chaining modes which do not have a filler byte
    /// </summary>
    function GetCipherModesWithoutFiller:TCipherModes;
  public
    { Public-Deklarationen }
  end;

var
  FormMain: TFormMain;

implementation

uses
  System.TypInfo, Generics.Collections,
  DECBaseClass, DECFormat,
  DECCipherFormats, DECCiphers, DECUtil, DECCipherInterface
  {$IFDEF Android}
  ,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.Helpers,
  Androidapi.JNI.App
  {$ENDIF};

{$R *.fmx}

function TFormMain.TryGetClipboardService(out Clipboard: IFMXClipboardService): Boolean;
begin
  Result := TPlatformServices.Current.SupportsPlatformService(IFMXClipboardService);
  if Result then
    Clipboard := IFMXClipboardService(TPlatformServices.Current.GetPlatformService(IFMXClipboardService));
end;

procedure TFormMain.StringToClipboard(const s: string);
var
  ClipBoard: IFMXClipboardService;
begin
  if TryGetClipboardService(ClipBoard) then
    ClipBoard.SetClipboard(s);
end;

procedure TFormMain.ButtonCopyClick(Sender: TObject);
var
  s : string;
begin
  s := '//start' + sLineBreak +
       'Cipher: ' +
         ComboBoxCipherAlgorithm.Items[ComboBoxCipherAlgorithm.ItemIndex] +
         sLineBreak +
       'Mode: ' +
         ComboBoxChainingMethod.Items[ComboBoxChainingMethod.ItemIndex] +
         sLineBreak +
       'Key: ' + EditKey.Text + sLineBreak +
       'Init vector: ' + EditInitVector.Text + sLineBreak +
       'Filler: ' + EditFiller.Text + sLineBreak +
       'Data to auhenticate: ' + EditAuthenticatedData.Text + sLineBreak +
       'Expected authentication result: ' +
         EditExpectedAuthenthicationResult.Text + sLineBreak +
       'Authentication result: ' +
         EditExpectedAuthenthicationResult.Text + sLineBreak +
       'Format input: ' +
         ComboBoxPlainTextFormatting.Items[ComboBoxPlainTextFormatting.ItemIndex] +
         sLineBreak +
       'Format output: ' +
         ComboBoxCipherTextFormatting.Items[ComboBoxCipherTextFormatting.ItemIndex] +
         sLineBreak +
       'Plain text: ' + EditPlainText.Text + sLineBreak +
       'Cipher text: ' + EditCipherText.Text + sLineBreak +
       'Demo version: ' + LabelVersion.Text + sLineBreak +
       '//end';
  StringToClipboard(s);
end;

procedure TFormMain.ButtonDecryptClick(Sender: TObject);
var
  Cipher               : TDECCipherModes;
  CipherTextFormatting : TDECFormatClass;
  PlainTextFormatting  : TDECFormatClass;
  CipherTextBuffer     : TBytes;
  PlainTextBuffer      : TBytes;
  AuthenticationOK     : Boolean; // for authenticated ciphers: is the calculated
                              // authentication result value correct?
begin
  if not GetFormatSettings(PlainTextFormatting, CipherTextFormatting) then
    exit;

  try
    Cipher := GetInitializedCipherInstance;

    try
      CipherTextBuffer  := System.SysUtils.BytesOf(EditCipherText.Text);

      if CipherTextFormatting.IsValid(CipherTextBuffer) then
      begin
        // Set all authentication related properties
        SetAuthenticationParams(Cipher);
        AuthenticationOK := false;

        try
          PlainTextBuffer := (Cipher as TDECFormattedCipher).DecodeBytes(
                            CipherTextFormatting.Decode(CipherTextBuffer));
          // in case of an authenticated cipher mode like cmGCM the Done method
          // will raise an exceptino when the calculated authentication value does
          // not match the given expected one
          (Cipher as TDECFormattedCipher).Done;
          // If we managed to get to here, the calculated authentication value is
          // ok if we're in an authenticated mode and have entered an expected value.
          if (length(EditExpectedAuthenthicationResult.Text) > 0) and
             (length(EditExpectedAuthenthicationResult.Text) =
              length(EditCalculatedAuthenticationValue.Text)) then
            AuthenticationOK := true;
        except
          On e:Exception do
            ShowMessage('Decryption failure:' + sLineBreak + e.Message,
                        TMsgDlgType.mtError);
        end;

        if Cipher.IsAuthenticated then
        begin
          EditCalculatedAuthenticationValue.Text :=
            StringOf(TFormat_HEXL.Encode(Cipher.CalculatedAuthenticationResult));

          if AuthenticationOK then
            ShowMessage('Calculated authentication result value is correct!',
                        TMsgDlgType.mtInformation);
        end;

        EditPlainText.Text := string(DECUtil.BytesToRawString(PlainTextFormatting.Encode(PlainTextBuffer)));
      end
      else
        ShowMessage('Input has wrong format', TMsgDlgType.mtError);
    finally
      Cipher.Free;
    end;
  except
    On e:Exception do
      ShowMessage('Decryption init failure: ' + e.Message, TMsgDlgType.mtError);
  end;
end;

procedure TFormMain.ButtonEncryptClick(Sender: TObject);
var
  Cipher           : TDECCipherModes;
  InputFormatting  : TDECFormatClass;
  OutputFormatting : TDECFormatClass;
  InputBuffer      : TBytes;
  OutputBuffer     : TBytes;
begin
  if not GetFormatSettings(InputFormatting, OutputFormatting) then
    exit;

  try
    Cipher := GetInitializedCipherInstance;

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
            ShowMessage('Encryption failure:' + sLineBreak + e.Message,
                        TMsgDlgType.mtError);
        end;

        EditCipherText.Text := string(DECUtil.BytesToRawString(OutputFormatting.Encode(OutputBuffer)));

        if Cipher.IsAuthenticated then
          EditCalculatedAuthenticationValue.Text :=
            StringOf(TFormat_HEXL.Encode(Cipher.CalculatedAuthenticationResult));
      end
      else
        ShowMessage('Input has wrong format', TMsgDlgType.mtError);
    finally
      Cipher.Free;
    end;
  except
    On e:Exception do
      ShowMessage('Encryption init failure: ' + e.Message, TMsgDlgType.mtError);
  end;
end;

procedure TFormMain.ComboBoxChainingMethodChange(Sender: TObject);
var
  NeedsFiller: Boolean;
begin
  // this on change handler is already called during form creation but at that
  // point the cipher algorithm combo may not have been fully initialized yet so
  // we must not update authentication status yet.
  if ComboBoxCipherAlgorithm.ItemIndex >= 0 then
    UpdateAuthenticationStatus;

  // does the selected mode requiring padding?
  // ECB mode doesn't need filler as we expect the user to enter completely
  // filled blocks
  NeedsFiller             := not (GetSelectedCipherMode in [cmGCM, cmECBx]);
  LabelFillerByte.Enabled := NeedsFiller;
  EditFiller.Enabled      := NeedsFiller;
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

  // this on change handler is already called during form creation but at that
  // point the block chaining mode combo has not been fully initialized yet so
  // we must not update authentication status yet.
  if ComboBoxChainingMethod.ItemIndex >= 0 then
    UpdateAuthenticationStatus;
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
  LayoutTop.Width := self.Width - 20;
  LayoutCipherSettings.Width := self.Width - 20;
  LayoutAuthentication.Width := self.Width - 20;
  LayoutEncrypt.Width := self.Width - 20;
end;

procedure TFormMain.FormShow(Sender: TObject);
begin
  // since all combo boxes are initialized now we can check authentication status
  UpdateAuthenticationStatus;
end;

function TFormMain.GetCipherInstance: TDECCipherModes;
begin
  // Find the class type of the selected cipher class and create an instance of it
  Result := TDECCipher.ClassByName(
    ComboBoxCipherAlgorithm.Items[ComboBoxCipherAlgorithm.ItemIndex]).Create as TDECCipherModes;

  Result.Mode := GetSelectedCipherMode;
end;

function TFormMain.GetCipherModesWithoutFiller: TCipherModes;
begin
  Result := [cmGCM, cmECBx];
end;

function TFormMain.GetFormatSettings(var PlainTextFormatting,
  CipherTextFormatting: TDECFormatClass): Boolean;
begin
  result := false;

  if ComboBoxPlainTextFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    PlainTextFormatting := TDECFormat.ClassByName(
      ComboBoxPlainTextFormatting.Items[ComboBoxPlainTextFormatting.ItemIndex]);
  end
  else
  begin
    ShowMessage('No plain text format selected', TMsgDlgType.mtError);
    exit;
  end;

  if ComboBoxCipherTextFormatting.ItemIndex >= 0 then
  begin
    // Find the class type of the selected formatting class and create an instance of it
    CipherTextFormatting := TDECFormat.ClassByName(
      ComboBoxCipherTextFormatting.Items[ComboBoxCipherTextFormatting.ItemIndex]);
  end
  else
  begin
    ShowMessage('No cipher text format selected', TMsgDlgType.mtError);
    exit;
  end;

  if EditKey.Text.IsEmpty or EditInitVector.Text.IsEmpty or
     (EditFiller.Text.IsEmpty and
      not (GetSelectedCipherMode in GetCipherModesWithoutFiller)) then
  begin
    ShowMessage('No key, initialization vector or filler byte given', TMsgDlgType.mtError);
    exit;
  end;

  result := true;
end;

function TFormMain.GetInitializedCipherInstance: TDECCipherModes;
var
  FillerByte : UInt8;
begin
  if not EditFiller.Text.IsEmpty then
  begin
    while length(EditFiller.Text) < 2 do
      EditFiller.Text := '0' + EditFiller.Text;

    FillerByte := StrToInt('0x' + EditFiller.Text)
  end
  else
    // we need to assume something to be able to call that init overload
    FillerByte := 0;

  if TFormat_HEXL.IsValid(RawByteString(EditInitVector.Text.ToLower)) and
     TFormat_HEXL.IsValid(RawByteString(EditKey.Text.ToLower)) then
  begin
    Result := GetCipherInstance;

    Result.Init(BytesOf(TFormat_HexL.Decode(RawByteString(EditKey.Text.ToLower))),
                BytesOf(TFormat_HexL.Decode(RawByteString(EditInitVector.Text.ToLower))),
                FillerByte);
  end
  else
    raise Exception.Create('No valid encryption key or init vector given!');
end;

function TFormMain.GetSelectedCipherMode: TCipherMode;
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
    ComboBoxPlainTextFormatting.Items.AddStrings(Formats);
    ComboBoxCipherTextFormatting.Items.AddStrings(Formats);

    if Formats.Count > 0 then
    begin
      if Formats.Find('TFormat_Copy', CopyIdx) then
      begin
        ComboBoxPlainTextFormatting.ItemIndex  := CopyIdx;
        ComboBoxCipherTextFormatting.ItemIndex := CopyIdx;
      end
      else
      begin
        ComboBoxPlainTextFormatting.ItemIndex  := 0;
        ComboBoxCipherTextFormatting.ItemIndex := 0;
      end;
    end;
  finally
    Formats.Free;
  end;
end;

function TFormMain.IsAuthenticatedCipher: Boolean;
var
  Cipher : TDECCipherModes;
begin
  Cipher := GetCipherInstance;
  try
    Result := Cipher.IsAuthenticated;
  finally
    Cipher.Free;
  end;
end;

procedure TFormMain.SetAuthenticationFieldsVisibility(Visible: Boolean);
begin
  LayoutAuthentication.Visible := Visible;

  // Adjust layout
  if Visible then
    LayoutEncrypt.Position.Y        := LayoutAuthentication.Position.Y +
                                       LayoutAuthentication.Height
  else
    LayoutEncrypt.Position.Y := LayoutCipherSettings.Position.Y +
                                LayoutCipherSettings.Height;

  self.VertScrollBox1.ClientHeight
end;

procedure TFormMain.SetAuthenticationParams(Cipher: TDECCipherModes);
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

procedure TFormMain.ShowMessage(Msg: string; MessageType: TMsgDlgType);
{$IF RTLVersion > 30}
var
  AsyncDlg : IFMXDialogServiceASync;
{$ENDIF}
begin
  {$IF RTLVersion > 30}
  if TPlatformServices.Current.SupportsPlatformService(IFMXDialogServiceAsync,
                                                       IInterface(AsyncDlg)) then
    AsyncDlg.MessageDialogAsync(Translate(Msg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], TMsgDlgBtn.mbOk, 0,
    procedure (const AResult: TModalResult)
    begin
    end);
  {$ELSE}
  MessageDlg(Translate(Msg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], 0);
  {$ENDIF}
end;

procedure TFormMain.UpdateAuthenticationStatus;
begin
  try
    if IsAuthenticatedCipher then
    begin
      SetAuthenticationFieldsVisibility(true);
      StringGridContext.Cells[1, 7] := 'yes';
    end
    else
    begin
      SetAuthenticationFieldsVisibility(false);
      StringGridContext.Cells[1, 7] := 'no';
    end;
  except
    On e:Exception do
    begin
      SetAuthenticationFieldsVisibility(false);
      StringGridContext.Cells[1, 7] := 'no';
      ShowMessage(e.Message, TMsgDlgType.mtError);
    end;
  end;
end;

end.
