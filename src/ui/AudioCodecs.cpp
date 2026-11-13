// Implementation of the vendored audio libraries (miniaudio + stb_vorbis),
// kept in its own translation unit so the project builds it with warnings
// off: their warnings are third-party and not ours to fix. Some (C4505,
// C4701) are reported at the end of the translation unit, so a
// push/pop around the includes in AudioPlayer.cpp could not scope them.
//
// miniaudio decodes WAV, FLAC and MP3 itself; stb_vorbis adds Ogg Vorbis when
// it is included around the implementation like this.
#ifdef _MSC_VER
#pragma warning(disable : 4505 4701)
#pragma warning(push, 0)
#endif
#define STB_VORBIS_HEADER_ONLY
#include "miniaudio/stb_vorbis.c"
#include "ui/AudioConfig.hpp"
#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio/miniaudio.h"
#undef STB_VORBIS_HEADER_ONLY
#include "miniaudio/stb_vorbis.c"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
