package team.balam.security.jwt.access;

import lombok.ToString;

@ToString
class RestUri {
    private String uri;
    private String[] uriArray;
    private int arrayLength;

    RestUri(String uri) {
        this.uri = uri;
        this.uriArray = uri.split("/");
        arrayLength = uriArray.length;
    }

    /**
     * HashMap 에서는 비교대상이 equals 의 주체가 된다.
     * map.put(a, A);
     * map.get(b) 가 내부에서 b.equals(a) 이렇게 실행 됨.
     * 그래서 * 를 검사하는 주체는 parameter 로 넘어온 값이 되어야 한다.(map 에 저장돼 있던 객체 이므로)
     */
    private boolean equalsAllPart(String[] otherUri) {
        if (arrayLength != otherUri.length) {
            return false;
        }

        for (int i = 0; i < arrayLength; ++i) {
            if (!"*".equals(otherUri[i]) && !otherUri[i].equals(uriArray[i])) {
                return false;
            }
        }

        return true;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof RestUri) {
            RestUri other = (RestUri) obj;

            if (this.uri.equals(other.uri)) {
                return true;
            } else {
                return equalsAllPart(other.uri.split("/"));
            }
        }

        return false;
    }
}
