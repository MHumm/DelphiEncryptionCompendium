{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2018 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
  Copyright (c) 2008 - 2012 Frederik A. Winkelsdorf (winkelsdorf [at] gmail [dot] com)
  Copyright (c) 1999 - 2008 Hagen Reddmann (HaReddmann [at] T-Online [dot] de)
  All rights reserved.

                               *** License ***

  This file is part of the Delphi Encryption Compendium (DEC). The DEC is free
  software being offered under a dual licensing scheme: BSD or MPL 1.1.

  The contents of this file are subject to the Mozilla Public License (MPL)
  Version 1.1 (the "License"); you may not use this file except in compliance
  with the License. You may obtain a copy of the License at
  http://www.mozilla.org/MPL/

  Alternatively, you may redistribute it and/or modify it under the terms of
  the following Berkeley Software Distribution (BSD) license:

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
  THE POSSIBILITY OF SUCH DAMAGE.

                        *** Export/Import Controls ***

  This is cryptographic software. Even if it is created, maintained and
  distributed from liberal countries in Europe (where it is legal to do this),
  it falls under certain export/import and/or use restrictions in some other
  parts of the world.

  PLEASE REMEMBER THAT EXPORT/IMPORT AND/OR USE OF STRONG CRYPTOGRAPHY
  SOFTWARE OR EVEN JUST COMMUNICATING TECHNICAL DETAILS ABOUT CRYPTOGRAPHY
  SOFTWARE IS ILLEGAL IN SOME PARTS OF THE WORLD. SO, WHEN YOU IMPORT THIS
  PACKAGE TO YOUR COUNTRY, RE-DISTRIBUTE IT FROM THERE OR EVEN JUST EMAIL
  TECHNICAL SUGGESTIONS OR EVEN SOURCE PATCHES TO THE AUTHOR OR OTHER PEOPLE
  YOU ARE STRONGLY ADVISED TO PAY CLOSE ATTENTION TO ANY EXPORT/IMPORT AND/OR
  USE LAWS WHICH APPLY TO YOU. THE AUTHORS OF THE DEC ARE NOT LIABLE FOR ANY
  VIOLATIONS YOU MAKE HERE. SO BE CAREFUL, IT IS YOUR RESPONSIBILITY.

*****************************************************************************}
unit MainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo, FMX.Layouts, FMX.ListBox,
  FMX.Edit;

type
  TMainForm = class(TForm)
    VertScrollBox1: TVertScrollBox;
    LayoutBottom: TLayout;
    Label3: TLabel;
    Label4: TLabel;
    ButtonCalc: TButton;
    EditInput: TEdit;
    EditOutput: TEdit;
    Label2: TLabel;
    Label5: TLabel;
    ComboBoxHashFunction: TComboBox;
    Label6: TLabel;
    ComboBoxInputFormatting: TComboBox;
    ComboBoxOutputFormatting: TComboBox;
    LayoutTop: TLayout;
    CheckBoxLiveCalc: TCheckBox;
    LabelVersion: TLabel;
    CheckBoxIsPasswordHash: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure FormResize(Sender: TObject);
    procedure ButtonCalcClick(Sender: TObject);
    procedure ComboBoxHashFunctionChange(Sender: TObject);
    procedure EditInputChangeTracking(Sender: TObject);
    procedure EditInputKeyUp(Sender: TObject; var Key: Word; var KeyChar: Char;
      Shift: TShiftState);
  private
    /// <summary>
    ///   Lists all available hash classes in the hash classes combo box
    /// </summary>
    procedure InitHashCombo;
    /// <summary>
    ///   Lists all available formatting classes in the formatting classes
    ///   combo boxes
    /// </summary>
    procedure InitFormatCombos;
    /// <summary>
    ///   Displays a given error message text in a non modal message box
    /// </summary>
    /// <param name="ErrorMsg">
    ///   Text to show as error message
    /// </param>
    procedure ShowErrorMessage(ErrorMsg: string);
  public
  end;

var
  FormMain: TMainForm;

implementation

uses
  DECBaseClass, DECHashBase, DECHash, DECFormatBase, DECFormat, DECUtil,
  Generics.Collections, FMX.Platform
  {$IFDEF Android}
  ,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.Helpers,
  Androidapi.JNI.App
  {$ENDIF};

{$R *.fmx}

procedure TMainForm.ButtonCalcClick(Sender: TObject);
var
  Hash             : TDECHash;
  InputFormatting  : TDECFormatClass;
  OutputFormatting : TDECFormatClass;
  InputBuffer      : TBytes;
  OutputBuffer     : TBytes;
begin
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
    ShowErrorMessage('No input format selected');
    exit;
  end;

  if ComboBoxHashFunction.ItemIndex >= 0 then
  begin
    // Find the class type of the selected hash class and create an instance of it
    Hash := TDECHash.ClassByName(
      ComboBoxHashFunction.Items[ComboBoxHashFunction.ItemIndex]).Create;

    try
      InputBuffer  := System.SysUtils.BytesOf(EditInput.Text);

      if InputFormatting.IsValid(InputBuffer) then
      begin
        OutputBuffer := Hash.CalcBytes(InputFormatting.Decode(InputBuffer));

        EditOutput.Text := string(DECUtil.BytesToRawString(OutputFormatting.Encode(OutputBuffer)));
      end
      else
        ShowErrorMessage('Input has wrong format');
    finally
      Hash.Free;
    end;
  end;
end;

procedure TMainForm.ShowErrorMessage(ErrorMsg: string);
var
  AsyncDlg : IFMXDialogServiceASync;
begin
  if TPlatformServices.Current.SupportsPlatformService(IFMXDialogServiceAsync,
                                                       IInterface(AsyncDlg)) then
    AsyncDlg.MessageDialogAsync(Translate(ErrorMsg),
             TMsgDlgType.mtError, [TMsgDlgBtn.mbOk], TMsgDlgBtn.mbOk, 0,
    procedure (const AResult: TModalResult)
    begin
    end);
end;

procedure TMainForm.ComboBoxHashFunctionChange(Sender: TObject);
begin
  CheckBoxIsPasswordHash.IsChecked :=
    TDECHash.ClassByName(
      ComboBoxHashFunction.Items[ComboBoxHashFunction.ItemIndex]).IsPasswordHash;
end;

procedure TMainForm.EditInputChangeTracking(Sender: TObject);
begin
  if CheckBoxLiveCalc.IsChecked then
    ButtonCalcClick(self);
end;

procedure TMainForm.EditInputKeyUp(Sender: TObject; var Key: Word;
  var KeyChar: Char; Shift: TShiftState);
begin
  if (Key = vkReturn) then
    ButtonCalcClick(self);
end;

procedure TMainForm.FormCreate(Sender: TObject);
var
  AppService : IFMXApplicationService;
begin
  if TPlatformServices.Current.SupportsPlatformService(IFMXApplicationService,
                                                       IInterface(AppService)) then
    LabelVersion.Text := format(LabelVersion.Text, [AppService.AppVersion])
  else
    LabelVersion.Text := format(LabelVersion.Text, ['']);

  InitHashCombo;
  InitFormatCombos;
end;

procedure TMainForm.InitFormatCombos;
var
  MyClass : TPair<Int64, TDECClass>;
  Formats : TStringList;
  CopyIdx : Integer;
begin
  Formats := TStringList.Create;

  try
    for MyClass in TDECFormat.ClassList do
      Formats.Add(MyClass.Value.GetShortClassName);

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

procedure TMainForm.InitHashCombo;
var
  MyClass : TPair<Int64, TDECClass>;
  Hashes  : TStringList;
begin
  Hashes := TStringList.Create;

  try
    for MyClass in TDECHash.ClassList do
      Hashes.Add(MyClass.Value.GetShortClassName);

    Hashes.Sort;
    ComboBoxHashFunction.Items.AddStrings(Hashes);

    if Hashes.Count > 0 then
      ComboBoxHashFunction.ItemIndex := 0;
  finally
    Hashes.Free;
  end;
end;

procedure TMainForm.FormResize(Sender: TObject);
begin
  LayoutTop.Width    := VertScrollBox1.Width;
  LayoutBottom.Width := VertScrollBox1.Width;
end;

end.
