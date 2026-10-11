object FormMain: TFormMain
  Left = 0
  Top = 0
  Caption = 'Cipher block modes demo'
  ClientHeight = 463
  ClientWidth = 873
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object p_Main: TPanel
    Left = 0
    Top = 33
    Width = 873
    Height = 430
    Align = alClient
    BevelOuter = bvNone
    TabOrder = 0
    ExplicitWidth = 800
    ExplicitHeight = 429
    object Splitter_Main: TSplitter
      Left = 329
      Top = 0
      Height = 430
      Beveled = True
    end
    object p_Left: TPanel
      Left = 0
      Top = 0
      Width = 329
      Height = 430
      Align = alLeft
      BevelOuter = bvNone
      TabOrder = 0
      ExplicitHeight = 429
      object Label1: TLabel
        Left = 0
        Top = 408
        Width = 329
        Height = 22
        Align = alBottom
        Alignment = taCenter
        AutoSize = False
        Caption = 'Original image'
      end
      object i_Original: TImage
        Left = 0
        Top = 0
        Width = 329
        Height = 408
        Align = alClient
        Proportional = True
        Stretch = True
      end
    end
    object p_Right: TPanel
      Left = 332
      Top = 0
      Width = 541
      Height = 430
      Align = alClient
      BevelOuter = bvNone
      TabOrder = 1
      ExplicitWidth = 468
      ExplicitHeight = 429
      object Label2: TLabel
        Left = 0
        Top = 408
        Width = 541
        Height = 22
        Align = alBottom
        Alignment = taCenter
        AutoSize = False
        Caption = 'Encrypted image'
        ExplicitWidth = 468
      end
      object i_Encrypted: TImage
        Left = 0
        Top = 0
        Width = 541
        Height = 408
        Align = alClient
        Proportional = True
        Stretch = True
        ExplicitWidth = 468
      end
    end
  end
  object p_Top: TPanel
    Left = 0
    Top = 0
    Width = 873
    Height = 33
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 1
    ExplicitLeft = 8
    ExplicitTop = 8
    ExplicitWidth = 800
    object Label3: TLabel
      Left = 320
      Top = 12
      Width = 34
      Height = 15
      Caption = 'Mode:'
    end
    object Label4: TLabel
      Left = 536
      Top = 12
      Width = 56
      Height = 15
      Caption = 'Init vector:'
    end
    object b_LoadImage: TButton
      Left = 0
      Top = 5
      Width = 145
      Height = 25
      Caption = '&Load image'
      TabOrder = 0
      OnClick = b_LoadImageClick
    end
    object b_EncryptImage: TButton
      Left = 151
      Top = 5
      Width = 145
      Height = 25
      Caption = '&Encrypt image'
      TabOrder = 1
      OnClick = b_EncryptImageClick
    end
    object cb_Mode: TComboBox
      Left = 368
      Top = 6
      Width = 145
      Height = 23
      Style = csDropDownList
      DropDownCount = 9
      ItemIndex = 0
      TabOrder = 2
      Text = 'ECB'
      Items.Strings = (
        'ECB'
        'CBC'
        'CTSx'
        'CFB8'
        'CFBx'
        'OFB8'
        'OFBx'
        'CFS8'
        'CFSx')
    end
    object tf_InitVector: TEdit
      Left = 598
      Top = 6
      Width = 179
      Height = 23
      TabOrder = 3
      Text = 'PickANewOne'
    end
  end
  object OpenPictureDialog: TOpenPictureDialog
    Filter = 'Bitmaps (*.bmp)|*.bmp'
    Options = [ofPathMustExist, ofFileMustExist, ofEnableSizing]
    Title = 'Load image'
    Left = 112
    Top = 129
  end
end
