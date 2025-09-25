package io.veggieshop.platform.http.error;

import io.veggieshop.problem.core.ProblemPayload;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;

import java.net.URI;

public final class ProblemHttpMapper {

    public ProblemDetail toProblemDetail(ProblemPayload p) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(
                HttpStatusCode.valueOf(p.status()),
                p.detail()
        );
        pd.setTitle(p.title());
        pd.setType(p.type());
        pd.setInstance(URI.create(p.instance()));
        p.extensions().forEach(pd::setProperty);
        return pd;
    }
}
