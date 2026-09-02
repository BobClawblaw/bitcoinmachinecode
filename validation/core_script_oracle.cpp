// validation/core_script_oracle.cpp -- Bitcoin Core's own script evaluator as
// a line oracle for tests/fuzz_script_diff.c (2026-09-02, audit 09-02 §6.9).
// Each stdin line:  <flags-hex> <sigversion> <txversion> <locktime> <sequence> <script-hex|-> [<stack-elem-hex|->...]
// Each stdout line: <1|0> <errcode> <n> <elem-hex|-> ...
// Built by validation/build_core_oracle.sh against the scratch Core tree; never part of the gate.
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <primitives/transaction.h>
#include <util/strencodings.h>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
static std::vector<unsigned char> unhex(const std::string& h){ if (h == "-") return {}; return ParseHex(h); }
static std::string hex(const std::vector<unsigned char>& v){ return v.empty() ? "-" : HexStr(v); }
int main(){
    std::string line;
    while (std::getline(std::cin, line)){
        std::istringstream in(line);
        std::string fl, sv, tv, lt, sq, sc; if (!(in >> fl >> sv >> tv >> lt >> sq >> sc)) { std::cout << "E parse\n"; continue; }
        uint64_t flags = std::stoull(fl, nullptr, 16);
        int sigv = std::stoi(sv);
        CMutableTransaction mtx; mtx.version = (uint32_t)std::stoul(tv); mtx.nLockTime = (uint32_t)std::stoul(lt);
        mtx.vin.resize(1); mtx.vin[0].nSequence = (uint32_t)std::stoul(sq); mtx.vout.resize(1); mtx.vout[0].nValue = 0;
        MutableTransactionSignatureChecker checker(&mtx, 0, 0, MissingDataBehavior::FAIL);
        std::vector<std::vector<unsigned char>> stack; std::string e;
        while (in >> e) stack.push_back(unhex(e));
        std::vector<unsigned char> sb = unhex(sc); CScript script(sb.begin(), sb.end());
        ScriptError err = SCRIPT_ERR_OK;
        SigVersion sig = sigv == 1 ? SigVersion::WITNESS_V0 : SigVersion::BASE;
        bool ok = EvalScript(stack, script, script_verify_flags::from_int(flags), checker, sig, &err);
        std::cout << (ok ? 1 : 0) << ' ' << (int)err << ' ' << stack.size();
        for (auto& s : stack) std::cout << ' ' << hex(s);
        std::cout << '\n' << std::flush;
    }
    return 0;
}
