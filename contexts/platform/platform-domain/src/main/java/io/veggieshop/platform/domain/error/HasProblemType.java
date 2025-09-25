package io.veggieshop.platform.domain.error;

import io.veggieshop.platform.domain.error.ProblemTypes.ProblemType;

public interface HasProblemType {
    ProblemType type();
}
