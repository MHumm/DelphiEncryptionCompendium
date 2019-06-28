{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2019 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
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

//------------------------------------------------------------------------------
// Reset Defines (do not change!)
//------------------------------------------------------------------------------

{$UNDEF NATIVEINT_UNDEFINED}

{$UNDEF PUREPASCAL}
{$UNDEF X86ASM}
{$UNDEF X64ASM}
{$UNDEF NO_ASM}

{$UNDEF AUTO_PRNG}
{$UNDEF INCLUDE_IDEA}
{$UNDEF DEC52_IDENTITY}
{$UNDEF DEC3_CMCTS}

{$UNDEF RESTORE_RANGECHECKS}
{$UNDEF RESTORE_OVERFLOWCHECKS}

//------------------------------------------------------------------------------
// User Configuration (feel free to edit)
//------------------------------------------------------------------------------

// Automatically use DEC's Pseudo Random Number Generator
{$DEFINE AUTO_PRNG} (* default ON *)

// if the compiler does not support assembler turn usage of and even if restrict
// it to Windows, as those non Windows platforms which actually do support ASM
// in Delphi do not use Intel x86 ASM
{$IFNDEF FPC}
  {$IFNDEF ASSEMBLER}
    {$DEFINE NO_ASM} (* default ON *)
  {$ELSE}
    {$IFDEF WINDOWS}
      {$UNDEFINE NO_ASM} (* default ON *)
    {$ELSE
      {$DEFINE NO_ASM} (* default ON *)
    {$ENDIF}
  {$ENDIF}
{$ELSE}
  // Turn ASM of for FPC as we do not know enough about ASM support on FPC
  {$DEFINE NO_ASM} (* default ON *)
{$ENDIF}

// Enable the following option to restore the *wrong* Identity behavior of
// DEC version 5.2. See TDECObject.Identity in DECBaseClass.pas for more details
{.$DEFINE DEC52_IDENTITY} (* default OFF *)

// Enable the following option to include the cmCTS3 block cipher mode in
// DECCipher. This mode is less secure due to the padding used on data smaller
// that cipher's block size but it might help when having to deal with
// data which needs to be compatible to the DEC 3.0 cmCTS mode. Not recommended!
{.$DEFINE DEC3_CMCTS} (* default OFF *)

/// <summary>
///   When building a Firemonkey project for non Windows platforms
///   ressource strings are not available. Enabling this enables some
///   alternative translation mechanism for exception messages based
///   on Firemonkey's TLang architecture
/// </summary>
{$IF DECLARED(FireMonkeyVersion)}
  {$DEFINE FMXTranslateableExceptions}
{$ENDIF}

//------------------------------------------------------------------------------
// Do NOT change anything below!
//------------------------------------------------------------------------------

{$DEFINE DELPHIORBCB}

//------------------------------------------------------------------------------
// FPC v2.x support (Experimental)
//------------------------------------------------------------------------------

{$IFDEF FPC}
  {$UNDEF DELPHIORBCB}

  {$DEFINE PUREPASCAL}

  {$DEFINE NATIVEINT_UNDEFINED}

  // use compatibility mode
  {$MODE DELPHI}

  // defines for Mac OS X
  {$IFDEF DARWIN}
    {$DEFINE MACOS}
    {$DEFINE ALIGN_STACK}
  {$ENDIF !DARWIN}
{$ENDIF FPC}

//------------------------------------------------------------------------------
// Architecture (x86ASM, x64ASM, PurePascal)
//------------------------------------------------------------------------------

{$IFDEF NO_ASM}
  // User config override (see top of this file)
  {$UNDEF X86ASM}
  {$UNDEF X64ASM}
  {$DEFINE PUREPASCAL}
{$ENDIF}

{$IFNDEF PUREPASCAL}
  // ignored by FPC (already in PurePascal mode as defined in FPC block above)
  {$IFDEF CPUX86}
    {$DEFINE X86ASM}
  {$ELSE !CPUX86}
    {$IFDEF CPUX64}
      {$DEFINE X64ASM}
    {$ELSE !CPUX64}
      {$DEFINE PUREPASCAL}
    {$ENDIF !CPUX64}
  {$ENDIF}
{$ENDIF !PUREPASCAL}

//------------------------------------------------------------------------------
// Delphi and C++ Builder
//------------------------------------------------------------------------------

{$IFDEF DELPHIORBCB}
  {$BOOLEVAL OFF} // short-circuit bool eval (Default OFF; Local Scope)

  {$IF CompilerVersion >= 20} // Delphi 2009 and newer
    {$IF CompilerVersion >= 21}   // Delphi 2010 and newer
      {$DEFINE DELPHI_2010_UP}
    {$ENDIF}
  {$ELSE}
    Sorry, but Delphi 2007 and lower are no longer supported!
  {$ENDIF}
{$ENDIF}

//------------------------------------------------------------------------------
// Asm Core
//------------------------------------------------------------------------------

{$IFDEF X86ASM}
  {$DEFINE THash_MD4_asm}
  {$DEFINE THash_MD5_asm}
  {$DEFINE THash_RipeMD128_asm}
  {$DEFINE THash_RipeMD160_asm}
  {$DEFINE THash_RipeMD256_asm}
  {$DEFINE THash_RipeMD320_asm}
  {$DEFINE THash_SHA_asm}
  {$DEFINE THash_SHA256_asm}
  {$DEFINE THashBaseHaval_asm}
  {$DEFINE THash_Panama_asm}
  {$DEFINE THashBaseWhirlpool_asm}
  {$DEFINE THash_Sapphire_asm}

  // The following asm optimized Hashes were incompatible with newer C++
  // Builder versions. Due to the fact that BCB detection is not implemented
  // in newer Delphi versions anymore, we leave them out for now:

  // {$DEFINE THash_MD2_asm}
  // {$DEFINE THash_SHA384_asm}
  // {$DEFINE THash_Tiger_asm}
  // {$DEFINE THash_Square_asm}
  // {$DEFINE THash_Snefru128_asm}
  // {$DEFINE THash_Snefru256_asm}
{$ENDIF}
