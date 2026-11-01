package com.soc.persistence;

import java.util.List;
import com.soc.model.IntrusionAlert;

public interface ImportSessionRepository {
    void startImport(ImportSession session);

    void completeImport(ImportSession session, List<IntrusionAlert> alerts);

    void finishImport(ImportSession session);

    List<ImportSession> recentImports(int limit);

    void markRunningImportsInterrupted();

}
