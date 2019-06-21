
interface AnalysisPass {
    public boolean doAnalysis();
}


class ArrayAnalysis implements AnalysisPass {
    Map<Long, Map<String, Set<String>>> m_smart;

    ArrayAnalysis (Map<Long, Map<String, Set<String>>> smart) {
        m_smart = smart;
    }

    public boolean doAnalysis() {
        return true;
    }

}

class StructAnalysis implements AnalysisPass {
    Map<Long, Map<String, Set<String>>> m_smart;
    StructAnalysis (Map<Long, Map<String, Set<String>>> smart) {
        m_smart = smart;
    }

    public boolean doAnalysis() {
        return true;
    }


}


class ClassAnalysis implements AnalysisPass {
    Map<Long, Map<String, Set<String>>> m_smart;
    ClassAnalysis (Map<Long, Map<String, Set<String>>> smart) {

    }

    public boolean doAnalysis() {
        return true;
    }

}

