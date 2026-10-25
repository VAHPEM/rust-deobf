# Ghidra post-script: print the rust-deobf annotations (plate comments + bookmarks) a prior
# run of ghidra_annotate.py left, so a headless run can be verified. Read-only.
# @category Rust
# @runtime PyGhidra
from ghidra.program.model.listing import CodeUnit

listing = currentProgram.getListing()
btm = currentProgram.getBookmarkManager()
n = 0
it = btm.getBookmarksIterator("Analysis")
for bm in it:
    if bm.getCategory() == "rust-deobf":
        n += 1
        print("BOOKMARK @%s : %s" % (bm.getAddress(), bm.getComment()))
        cu = listing.getCodeUnitAt(bm.getAddress())
        if cu is not None:
            pc = cu.getComment(CodeUnit.PLATE_COMMENT)
            if pc:
                print("PLATE @%s:\n%s" % (bm.getAddress(), pc))
        f = currentProgram.getFunctionManager().getFunctionContaining(bm.getAddress())
        if f is not None:
            print("FUNC name now: %s" % f.getName())
print("rust-deobf annotations found: %d" % n)
