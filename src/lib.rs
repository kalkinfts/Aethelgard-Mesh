use std::fmt;

pub const MAX_GRAPH_NODES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    EmptyGraph,
    TooManyNodes { actual: usize, maximum: usize },
    NonSquareMatrix { row: usize, expected: usize, actual: usize },
    InvalidNode { node: usize, node_count: usize },
    DistanceOverflow,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGraph => write!(f, "graph must contain at least one node"),
            Self::TooManyNodes { actual, maximum } => {
                write!(f, "graph has {actual} nodes; maximum is {maximum}")
            }
            Self::NonSquareMatrix { row, expected, actual } => write!(
                f,
                "graph row {row} has {actual} entries; expected {expected}"
            ),
            Self::InvalidNode { node, node_count } => {
                write!(f, "node index {node} is outside graph size {node_count}")
            }
            Self::DistanceOverflow => write!(f, "shortest-path distance overflowed u64"),
        }
    }
}

impl std::error::Error for GraphError {}

/// Returns the shortest distance in a directed weighted graph.
/// Zero means no edge; positive values are edge weights.
/// Returns Ok(None) when the destination is unreachable.
pub fn shortest_path(
    graph: &[Vec<u64>],
    start: usize,
    end: usize,
) -> Result<Option<u64>, GraphError> {
    let node_count = graph.len();

    if node_count == 0 {
        return Err(GraphError::EmptyGraph);
    }
    if node_count > MAX_GRAPH_NODES {
        return Err(GraphError::TooManyNodes {
            actual: node_count,
            maximum: MAX_GRAPH_NODES,
        });
    }

    for (row_index, row) in graph.iter().enumerate() {
        if row.len() != node_count {
            return Err(GraphError::NonSquareMatrix {
                row: row_index,
                expected: node_count,
                actual: row.len(),
            });
        }
    }

    for node in [start, end] {
        if node >= node_count {
            return Err(GraphError::InvalidNode { node, node_count });
        }
    }

    let mut distances = vec![None; node_count];
    let mut visited = vec![false; node_count];
    distances[start] = Some(0_u64);

    for _ in 0..node_count {
        let current = (0..node_count)
            .filter(|&node| !visited[node])
            .filter_map(|node| distances[node].map(|distance| (node, distance)))
            .min_by_key(|&(_, distance)| distance)
            .map(|(node, _)| node);

        let Some(current) = current else {
            break;
        };

        if current == end {
            return Ok(distances[current]);
        }

        visited[current] = true;

        for (neighbor, &weight) in graph[current].iter().enumerate() {
            if weight == 0 || visited[neighbor] {
                continue;
            }

            let candidate = distances[current]
                .expect("selected nodes always have a known distance")
                .checked_add(weight)
                .ok_or(GraphError::DistanceOverflow)?;

            if distances[neighbor].is_none_or(|known| candidate < known) {
                distances[neighbor] = Some(candidate);
            }
        }
    }

    Ok(distances[end])
}

#[cfg(test)]
mod tests {
    use super::{shortest_path, GraphError, MAX_GRAPH_NODES};

    #[test]
    fn finds_shortest_path_across_multiple_edges() {
        let graph = vec![vec![0, 4, 0], vec![4, 0, 8], vec![0, 8, 0]];
        assert_eq!(shortest_path(&graph, 0, 2), Ok(Some(12)));
    }

    #[test]
    fn returns_zero_for_same_start_and_end() {
        assert_eq!(shortest_path(&[vec![0]], 0, 0), Ok(Some(0)));
    }

    #[test]
    fn returns_none_when_destination_is_unreachable() {
        let graph = vec![vec![0, 2, 0], vec![0, 0, 0], vec![0, 0, 0]];
        assert_eq!(shortest_path(&graph, 0, 2), Ok(None));
    }

    #[test]
    fn rejects_an_empty_graph() {
        assert_eq!(shortest_path(&[], 0, 0), Err(GraphError::EmptyGraph));
    }

    #[test]
    fn rejects_a_non_square_matrix() {
        let graph = vec![vec![0, 1], vec![1]];
        assert!(matches!(
            shortest_path(&graph, 0, 1),
            Err(GraphError::NonSquareMatrix { row: 1, .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_node_indices() {
        assert_eq!(
            shortest_path(&[vec![0]], 0, 1),
            Err(GraphError::InvalidNode { node: 1, node_count: 1 })
        );
    }

    #[test]
    fn rejects_graphs_over_the_configured_limit() {
        let graph = vec![vec![0; MAX_GRAPH_NODES + 1]; MAX_GRAPH_NODES + 1];
        assert!(matches!(
            shortest_path(&graph, 0, 0),
            Err(GraphError::TooManyNodes { .. })
        ));
    }

    #[test]
    fn supports_a_path_whose_distance_is_u64_max() {
        let graph = vec![vec![0, u64::MAX], vec![0, 0]];
        assert_eq!(shortest_path(&graph, 0, 1), Ok(Some(u64::MAX)));
    }

    #[test]
    fn reports_distance_overflow_instead_of_wrapping() {
        let graph = vec![
            vec![0, u64::MAX - 1, 0],
            vec![0, 0, 2],
            vec![0, 0, 0],
        ];
        assert_eq!(
            shortest_path(&graph, 0, 2),
            Err(GraphError::DistanceOverflow)
        );
    }

    #[test]
    fn treats_edges_as_directed() {
        let graph = vec![vec![0, 7], vec![0, 0]];
        assert_eq!(shortest_path(&graph, 0, 1), Ok(Some(7)));
        assert_eq!(shortest_path(&graph, 1, 0), Ok(None));
    }
}
