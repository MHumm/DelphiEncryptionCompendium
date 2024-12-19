object FormMain: TFormMain
  Left = 0
  Top = 0
  Caption = 'Progress Test for File Encrypt/Decrypt'
  ClientHeight = 319
  ClientWidth = 635
  Color = clBtnFace
  Constraints.MinHeight = 226
  Constraints.MinWidth = 350
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    635
    319)
  TextHeight = 13
  object ProgressBar1: TProgressBar
    Left = 8
    Top = 193
    Width = 619
    Height = 17
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 0
  end
  object RadioButtonMethod: TRadioButton
    Left = 8
    Top = 216
    Width = 193
    Height = 17
    Caption = 'Use method as progress event'
    Checked = True
    TabOrder = 1
    TabStop = True
  end
  object RadioButtonProcedure: TRadioButton
    Left = 8
    Top = 248
    Width = 193
    Height = 17
    Caption = 'Use procedure as progress event'
    TabOrder = 2
  end
  object RadioButtonAnonMethod: TRadioButton
    Left = 8
    Top = 282
    Width = 233
    Height = 17
    Caption = 'Use anonymous method as progress event'
    TabOrder = 3
  end
  object CheckBoxPKCS7: TCheckBox
    Left = 8
    Top = 98
    Width = 121
    Height = 17
    Anchors = [akTop, akRight]
    Caption = 'Use PKCS7'
    TabOrder = 4
  end
  object PageControl1: TPageControl
    Left = 8
    Top = 130
    Width = 619
    Height = 57
    ActivePage = tabEncrypt
    TabOrder = 5
    object tabEncrypt: TTabSheet
      Caption = 'Encrypt AES256-CBC'
      DesignSize = (
        611
        29)
      object ButtonEncrypt: TButton
        Left = 7
        Top = 3
        Width = 75
        Height = 25
        Caption = 'Encrypt'
        TabOrder = 0
        OnClick = ButtonEncryptClick
      end
      object EditEncrypt: TEdit
        Left = 88
        Top = 5
        Width = 523
        Height = 21
        Anchors = [akLeft, akTop, akRight]
        TabOrder = 1
        Text = 'D:\Test.txt'
      end
    end
    object tabDecrypt: TTabSheet
      Caption = 'Decrypt AES256-CBC'
      ImageIndex = 1
      DesignSize = (
        611
        29)
      object ButtonDecrypt: TButton
        Left = 7
        Top = 3
        Width = 75
        Height = 25
        Caption = 'Decrypt'
        TabOrder = 0
        OnClick = ButtonDecryptClick
      end
      object EditDecrypt: TEdit
        Left = 88
        Top = 5
        Width = 523
        Height = 21
        Anchors = [akLeft, akTop, akRight]
        TabOrder = 1
        Text = 'D:\Test.enc'
      end
    end
  end
  object EditKey: TLabeledEdit
    Left = 8
    Top = 24
    Width = 529
    Height = 21
    EditLabel.Width = 99
    EditLabel.Height = 13
    EditLabel.Caption = 'Key (base64 format)'
    TabOrder = 6
    Text = ''
  end
  object EditIV: TLabeledEdit
    Left = 8
    Top = 63
    Width = 529
    Height = 21
    EditLabel.Width = 141
    EditLabel.Height = 13
    EditLabel.Caption = 'Initial Vector (base64 format)'
    TabOrder = 7
    Text = ''
  end
  object ButtonCreateKeyAndIV: TButton
    Left = 552
    Top = 24
    Width = 75
    Height = 64
    Caption = 'Create Key and IV'
    TabOrder = 8
    WordWrap = True
    OnClick = ButtonCreateKeyAndIVClick
  end
end
