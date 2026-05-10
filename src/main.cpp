#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include "pl/Gloss.h"
#include "pl/Signature.h"

// ─────────────────────────────────────────────────────────────────
//  RenderScale Mod para Minecraft Bedrock Edition (ARM64)
//  Fixa o render scale em 0.5 — metade da resolução nativa.
//  Mesmo padrão do Better-Brightness.
//
//  Como funciona:
//    O MCBE lê o render scale de uma função interna.
//    Patchamos as instruções ARM64 que carregam o valor 1.0f
//    e substituímos por 0.5f diretamente na memória.
//
//  Se não funcionar na sua versão do MCBE:
//    1. Abra o libminecraftpe.so no IDA/Ghidra
//    2. Busque pela string "render_resolution_scale"
//    3. Encontre a função que retorna o float
//    4. Atualize RENDER_SCALE_SIGNATURE com os bytes dessa função
// ─────────────────────────────────────────────────────────────────

// Assinatura da função que controla o render scale no MCBE.
// Padrão encontrado em builds ARM64 do MCBE 1.20.x ~ 1.21.x
static const char* RENDER_SCALE_SIGNATURE =
    "? ? ? 1E ? ? ? 1E ? ? ? 1E ? ? ? 52 ? ? ? 72 ? ? ? 52 ? ? ? 1E ? ? ? 1E";

// ── Valor alvo: 0.5 ─────────────────────────────────────────────
//
//  0.5f em IEEE 754 = 0x3F000000
//
//  Instrução ARM64 para carregar 0.5 num registro float:
//    FMOV S0, #0.5  →  0x1E2E1000
//
//  Para outros valores:
//    0.25f → FMOV S0, #0.25 → 0x1E241000
//    0.75f → FMOV S0, #0.75 → 0x1E361000
//    1.0f  → FMOV S0, #1.0  → 0x1E2E1000  (padrão do jogo)
//
// Offsets dentro da função encontrada pelo signature scan
constexpr ptrdiff_t OFFSET_SCALE_INSN = 0;  // primeiro FMOV da função

// Instrução que substitui: FMOV S0, #0.5
constexpr uint32_t FMOV_S0_HALF = 0x1E2E1000;

// ── Patch de memória (idêntico ao Better-Brightness) ─────────────
static bool PatchMemory(void* addr, uint32_t insn) {
    uintptr_t page_start = (uintptr_t)addr & ~(uintptr_t)4095;
    size_t    page_size  = (sizeof(insn) + 4095) & ~(size_t)4095;
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;
    memcpy(addr, &insn, sizeof(insn));
    __builtin___clear_cache((char*)addr, (char*)addr + sizeof(insn));
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);
    return true;
}

// ── Hook alternativo via GlossHook ───────────────────────────────
//  Caso o patch direto não funcione, hookamos a função que retorna
//  o render scale e forçamos o retorno de 0.5f.

static float (*g_orig_getRenderScale)(void* self) = nullptr;

static float hook_getRenderScale(void* self) {
    return 0.5f;
}

static bool TryHookRenderScale() {
    // Tentativa 1: busca pelo símbolo exportado
    void* lib = dlopen("libminecraftpe.so", RTLD_NOLOAD);
    if (!lib) return false;

    // Nomes possíveis da função em diferentes versões do MCBE
    const char* symbols[] = {
        "_ZN7Options13getRenderScaleEv",
        "_ZNK7Options13getRenderScaleEv",
        "_ZN11VideoOptions13getRenderScaleEv",
        nullptr
    };

    for (int i = 0; symbols[i]; i++) {
        void* sym = (void*)GlossSymbol((GHandle)lib, symbols[i], nullptr);
        if (sym) {
            GlossHook(sym, (void*)hook_getRenderScale, (void**)&g_orig_getRenderScale);
            return true;
        }
    }
    return false;
}

// ── Patch direto por signature ────────────────────────────────────
static bool TryPatchRenderScale() {
    uintptr_t base = pl::signature::pl_resolve_signature(
        RENDER_SCALE_SIGNATURE, "libminecraftpe.so");
    if (base == 0) return false;

    return PatchMemory(
        reinterpret_cast<void*>(base + OFFSET_SCALE_INSN),
        FMOV_S0_HALF
    );
}

// ── Entry point ──────────────────────────────────────────────────
__attribute__((constructor))
void RenderScale_Init() {
    GlossInit(true);

    // Tenta hook primeiro (mais confiável entre versões)
    if (TryHookRenderScale()) return;

    // Fallback: patch direto de instrução
    TryPatchRenderScale();
}
